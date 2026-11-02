//go:build windows

package intercept

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/engine"
	"github.com/DestroyersTaken/SentinelProxy/internal/procinfo"
)

// Windows backend: WinDivert captures outbound packets at the network
// layer and the NAT core (nat.go) reflects redirected flows into local
// TCP/UDP relays. A socket-layer handle learns the owning PID of each
// connect() early, and a sniff-only handle learns hostnames from DNS
// responses and counts download bytes of bypassed flows.

type winInterceptor struct {
	eng     *engine.Engine
	nat     *nat
	net     *wdHandle
	sock    *wdHandle
	sniff   *wdHandle
	tcpLn   net.Listener
	udpLn   *net.UDPConn
	wg      sync.WaitGroup
	closed  atomic.Bool
	errors  atomic.Uint64
	lastErr atomic.Value
	fakeDNS bool
}

func available() (bool, string) {
	if _, err := loadWinDivert(); err != nil {
		return false, err.Error()
	}
	if !isElevated() {
		return false, "run SentinelProxy as administrator to capture traffic system-wide"
	}
	return true, ""
}

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func start(eng *engine.Engine, s config.Settings) (Interceptor, error) {
	w, err := loadWinDivert()
	if err != nil {
		return nil, err
	}
	tcpLn, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		tcpLn.Close()
		return nil, err
	}
	tcpPort := uint16(tcpLn.Addr().(*net.TCPAddr).Port)
	udpPort := uint16(udpLn.LocalAddr().(*net.UDPAddr).Port)
	ensureFirewallRule(eng)

	wi := &winInterceptor{eng: eng, tcpLn: tcpLn, udpLn: udpLn, fakeDNS: s.DNS.Mode == config.DNSFakeIP}
	hooks := Hooks{
		Classify: eng.Classify,
		OwnerPID: func(udp bool, local netip.AddrPort) (uint32, bool) {
			if udp {
				return procinfo.PIDOfUDP(local)
			}
			return procinfo.PIDOfTCP(local)
		},
		App:          procinfo.AppByPID,
		SelfPID:      procinfo.Self,
		FinishBypass: eng.Tracker.Close,
		InterceptUDP: s.InterceptUDP,
	}
	if wi.fakeDNS {
		hooks.AnswerDNS = eng.AnswerDNS
	}
	wi.nat = newNAT(hooks, tcpPort, udpPort)

	ipf := "ip"
	if s.InterceptIPv6 {
		ipf = "(ip or ipv6)"
	}
	udpf := ""
	if s.InterceptUDP || wi.fakeDNS {
		udpf = fmt.Sprintf(" or (udp and udp.DstPort != 67 and udp.DstPort != 68 and udp.DstPort != 546 and udp.DstPort != 547) or udp.SrcPort == %d", udpPort)
	}
	filter := fmt.Sprintf("outbound and not loopback and not impostor and %s and (tcp%s)", ipf, udpf)
	wi.net, err = w.Open(filter, layerNetwork, 0, 0)
	if err != nil {
		tcpLn.Close()
		udpLn.Close()
		return nil, err
	}
	wi.net.SetParam(paramQueueLength, 16384)
	wi.net.SetParam(paramQueueTime, 2000)
	wi.net.SetParam(paramQueueSize, 32<<20)

	// Optional helpers: failures only cost accuracy.
	if h, err := w.Open("event == CONNECT and not loopback", layerSocket, 1, flagSniff|flagRecvOnly); err == nil {
		wi.sock = h
	} else {
		eng.Log.Warnf("WinDivert socket layer unavailable (%v); using connection table lookups", err)
	}
	if h, err := w.Open("inbound and not loopback and (udp.SrcPort == 53 or tcp)", layerNetwork, 2, flagSniff|flagRecvOnly); err == nil {
		h.SetParam(paramQueueLength, 16384)
		wi.sniff = h
	}
	if wi.fakeDNS {
		flushDNS()
	}

	wi.wg.Add(4)
	go wi.packetLoop()
	go wi.acceptTCP()
	go wi.serveUDP()
	go wi.gcLoop()
	if wi.sock != nil {
		wi.wg.Add(1)
		go wi.socketLoop()
	}
	if wi.sniff != nil {
		wi.wg.Add(1)
		go wi.sniffLoop()
	}
	eng.Log.Infof("Capturing traffic system-wide with WinDivert (TCP relay %d, UDP relay %d)", tcpPort, udpPort)
	return wi, nil
}

func (wi *winInterceptor) Name() string { return "WinDivert" }

func (wi *winInterceptor) Stats() Stats {
	st := Stats{Packets: wi.nat.packets.Load(), Redirected: wi.nat.redirected.Load(), Bypassed: wi.nat.bypassed.Load(),
		DNSFaked: wi.nat.faked.Load(), Flows: wi.nat.size(), Errors: wi.errors.Load()}
	if v, ok := wi.lastErr.Load().(string); ok {
		st.LastError = v
	}
	return st
}

func (wi *winInterceptor) fail(err error) {
	wi.errors.Add(1)
	wi.lastErr.Store(err.Error())
}

func (wi *winInterceptor) Close() error {
	if wi.closed.Swap(true) {
		return nil
	}
	for _, h := range []*wdHandle{wi.net, wi.sock, wi.sniff} {
		if h != nil {
			h.Shutdown()
		}
	}
	wi.tcpLn.Close()
	wi.udpLn.Close()
	wi.wg.Wait()
	for _, h := range []*wdHandle{wi.net, wi.sock, wi.sniff} {
		if h != nil {
			h.Close()
		}
	}
	if wi.fakeDNS {
		flushDNS() // drop fake answers cached by Windows
	}
	return nil
}

func (wi *winInterceptor) packetLoop() {
	defer wi.wg.Done()
	buf := make([]byte, 65535)
	var addr wdAddress
	for {
		n, err := wi.net.Recv(buf, &addr)
		if err != nil {
			if wi.closed.Load() || isShutdown(err) {
				return
			}
			wi.fail(err)
			continue
		}
		pkt := buf[:n]
		res := wi.nat.outbound(pkt)
		if res.Inject != nil {
			reply := addr
			reply.setOutbound(false)
			wi.net.CalcChecksums(res.Inject, &reply)
			if err := wi.net.Send(res.Inject, &reply); err != nil {
				wi.fail(err)
			}
		}
		if res.Drop {
			continue
		}
		if res.Inbound {
			addr.setOutbound(false)
		}
		if res.Modified {
			wi.net.CalcChecksums(pkt, &addr)
		}
		if err := wi.net.Send(pkt, &addr); err != nil && !wi.closed.Load() {
			wi.fail(err)
		}
	}
}

func (wi *winInterceptor) socketLoop() {
	defer wi.wg.Done()
	var addr wdAddress
	for {
		if err := wi.sock.RecvEvent(&addr); err != nil {
			if wi.closed.Load() || isShutdown(err) {
				return
			}
			continue
		}
		local := netip.AddrPortFrom(addr.localAddr(), addr.localPort())
		switch addr.protocol() {
		case protoTCP:
			procinfo.Remember(true, local, addr.processID())
		case protoUDP:
			procinfo.Remember(false, local, addr.processID())
		}
	}
}

func (wi *winInterceptor) sniffLoop() {
	defer wi.wg.Done()
	buf := make([]byte, 65535)
	var addr wdAddress
	for {
		n, err := wi.sniff.Recv(buf, &addr)
		if err != nil {
			if wi.closed.Load() || isShutdown(err) {
				return
			}
			continue
		}
		pkt := buf[:n]
		p, ok := parsePacket(pkt)
		if !ok {
			continue
		}
		if p.proto == protoUDP && p.sport == 53 {
			wi.eng.ObserveDNSResponse(p.udpPayload(pkt))
			continue
		}
		wi.nat.inboundBypass(pkt)
	}
}

func (wi *winInterceptor) gcLoop() {
	defer wi.wg.Done()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for !wi.closed.Load() {
		<-t.C
		wi.nat.gc()
	}
}

func peerOf(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.TCPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	case *net.UDPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

func (wi *winInterceptor) acceptTCP() {
	defer wi.wg.Done()
	for {
		c, err := wi.tcpLn.Accept()
		if err != nil {
			if wi.closed.Load() {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		f := wi.nat.relayFlow(false, peerOf(c.RemoteAddr()))
		if f == nil {
			// Not a reflected flow: someone reached the relay port directly.
			c.Close()
			continue
		}
		go wi.eng.HandleTCP(c, engine.Flow{Network: "tcp", Inbound: "intercept", Src: f.local, Dst: f.remote, App: f.app}, nil)
	}
}

func (wi *winInterceptor) serveUDP() {
	defer wi.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := wi.udpLn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if wi.closed.Load() {
				return
			}
			continue
		}
		peer := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		f := wi.nat.relayFlow(true, peer)
		if f == nil {
			continue
		}
		to := from
		wi.eng.HandleUDP(engine.Flow{Network: "udp", Inbound: "intercept", Src: f.local, Dst: f.remote, App: f.app}, buf[:n], func(p []byte) {
			_, _ = wi.udpLn.WriteToUDPAddrPort(p, to)
		})
	}
}

// ensureFirewallRule allows the relay to receive reflected connections on
// every network profile (VPN adapters are usually "Public", where Windows
// drops inbound traffic for apps that were only allowed on Private).
func ensureFirewallRule(eng *engine.Engine) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	h := fnv.New32a()
	h.Write([]byte(strings.ToLower(exe)))
	name := fmt.Sprintf("SentinelProxy relay %08x", h.Sum32())
	run := func(args ...string) error {
		cmd := exec.Command("netsh", append([]string{"advfirewall", "firewall"}, args...)...)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		return cmd.Run()
	}
	if run("show", "rule", "name="+name) == nil {
		return
	}
	if err := run("add", "rule", "name="+name, "dir=in", "action=allow", "program="+exe, "enable=yes", "profile=any",
		"description=Lets SentinelProxy's relay receive redirected connections on all network profiles"); err != nil {
		eng.Log.Warnf("Could not add the Windows Firewall rule for the relay (%v). If capture fails on VPN or public networks, allow SentinelProxy through the firewall for all profiles.", err)
		return
	}
	eng.Log.Infof("Added Windows Firewall rule %q", name)
}

var procFlushDNS = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

func flushDNS() {
	if procFlushDNS.Find() == nil {
		procFlushDNS.Call()
	}
}
