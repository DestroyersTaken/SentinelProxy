package intercept

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DestroyersTaken/SentinelProxy/internal/engine"
	"github.com/DestroyersTaken/SentinelProxy/internal/match"
)

// This file holds the platform-independent half of the WinDivert backend:
// packet parsing and the "reflection" NAT that turns an app's outbound
// packets into inbound packets for the local relay and back. It works on raw
// IP packets so it can be unit-tested anywhere.
//
//   app      L:lp -> R:rp            (captured outbound)
//   rewrite  R:lp -> L:relay         (re-injected inbound, reaches relay)
//   relay    L:relay -> R:lp         (captured outbound)
//   rewrite  R:rp -> L:lp            (re-injected inbound, reaches app)

const (
	protoTCP = 6
	protoUDP = 17

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

type packet struct {
	v6       bool
	proto    uint8
	ipLen    int // IP header length
	src, dst netip.Addr
	sport    uint16
	dport    uint16
	flags    uint8 // TCP flags
	payload  int   // L4 payload length
}

func parsePacket(b []byte) (packet, bool) {
	var p packet
	if len(b) < 20 {
		return p, false
	}
	switch b[0] >> 4 {
	case 4:
		p.ipLen = int(b[0]&0x0f) * 4
		if p.ipLen < 20 || len(b) < p.ipLen {
			return p, false
		}
		if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return p, false // fragment: leave alone
		}
		p.proto = b[9]
		p.src = netip.AddrFrom4([4]byte(b[12:16]))
		p.dst = netip.AddrFrom4([4]byte(b[16:20]))
	case 6:
		if len(b) < 40 {
			return p, false
		}
		p.v6 = true
		p.ipLen = 40
		p.proto = b[6] // extension headers are not followed: such packets pass untouched
		p.src = netip.AddrFrom16([16]byte(b[8:24]))
		p.dst = netip.AddrFrom16([16]byte(b[24:40]))
	default:
		return p, false
	}
	l4 := b[p.ipLen:]
	switch p.proto {
	case protoTCP:
		if len(l4) < 20 {
			return p, false
		}
		off := int(l4[12]>>4) * 4
		if off < 20 || len(l4) < off {
			return p, false
		}
		p.flags = l4[13]
		p.payload = len(l4) - off
	case protoUDP:
		if len(l4) < 8 {
			return p, false
		}
		p.payload = len(l4) - 8
	default:
		return p, false
	}
	p.sport = binary.BigEndian.Uint16(l4[0:2])
	p.dport = binary.BigEndian.Uint16(l4[2:4])
	return p, true
}

func (p *packet) udpPayload(b []byte) []byte { return b[p.ipLen+8:] }

func writeAddrs(b []byte, p *packet, src, dst netip.Addr) {
	if p.v6 {
		s, d := src.As16(), dst.As16()
		copy(b[8:24], s[:])
		copy(b[24:40], d[:])
	} else {
		s, d := src.As4(), dst.As4()
		copy(b[12:16], s[:])
		copy(b[16:20], d[:])
	}
	p.src, p.dst = src, dst
}

func writePorts(b []byte, p *packet, sport, dport uint16) {
	binary.BigEndian.PutUint16(b[p.ipLen:], sport)
	binary.BigEndian.PutUint16(b[p.ipLen+2:], dport)
	p.sport, p.dport = sport, dport
}

// buildUDPReply builds an inbound UDP packet answering p (addresses and
// ports swapped) with a new payload. Checksums are left for the caller.
func buildUDPReply(orig []byte, p packet, payload []byte) []byte {
	out := make([]byte, p.ipLen+8+len(payload))
	copy(out, orig[:p.ipLen])
	q := p
	writeAddrs(out, &q, p.dst, p.src)
	writePorts(out, &q, p.dport, p.sport)
	binary.BigEndian.PutUint16(out[p.ipLen+4:], uint16(8+len(payload)))
	copy(out[p.ipLen+8:], payload)
	if p.v6 {
		binary.BigEndian.PutUint16(out[4:6], uint16(8+len(payload)))
	} else {
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[8] = 64 // TTL
	}
	return out
}

// flowKey identifies a flow by the app's local port, the remote IP and
// the protocol. The relay sees exactly (remote IP, local port).
type flowKey struct {
	udp  bool
	port uint16
	peer netip.Addr
}

type flow struct {
	local    netip.AddrPort // L:lp
	remote   netip.AddrPort // R:rp, the original destination
	app      match.AppInfo
	redirect bool
	self     bool
	bypass   *engine.Conn
	last     atomic.Int64
	fins     atomic.Uint32
	closedAt atomic.Int64
}

// Hooks lets the NAT core reach the rest of the system (stubbed in tests).
type Hooks struct {
	Classify     func(engine.Flow) engine.Verdict
	OwnerPID     func(udp bool, local netip.AddrPort) (uint32, bool)
	App          func(pid uint32) match.AppInfo
	SelfPID      uint32
	AnswerDNS    func(query []byte) ([]byte, bool)
	FinishBypass func(c *engine.Conn)
	InterceptUDP bool
}

// Result tells the capture loop what to do with a packet.
type Result struct {
	Drop     bool
	Inbound  bool   // re-inject as inbound (after rewrite)
	Modified bool   // checksums must be recomputed
	Inject   []byte // inject this inbound packet instead (DNS answers)
}

type nat struct {
	hooks    Hooks
	relayTCP uint16
	relayUDP uint16

	mu    sync.RWMutex
	flows map[flowKey]*flow

	packets, redirected, bypassed, faked atomic.Uint64
}

func newNAT(h Hooks, relayTCP, relayUDP uint16) *nat {
	return &nat{hooks: h, relayTCP: relayTCP, relayUDP: relayUDP, flows: map[flowKey]*flow{}}
}

func unmap(a netip.Addr) netip.Addr { return a.Unmap() }

func isSpecial(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsLoopback() ||
		a.IsUnspecified() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || (a.Is4() && a.As4()[3] == 255)
}

// outbound handles one captured outbound packet.
func (n *nat) outbound(b []byte) Result {
	n.packets.Add(1)
	p, ok := parsePacket(b)
	if !ok {
		return Result{}
	}
	udp := p.proto == protoUDP
	now := time.Now().UnixNano()

	// 1. Replies from our relays: restore the original destination as source.
	if (!udp && p.sport == n.relayTCP) || (udp && p.sport == n.relayUDP) {
		f := n.lookup(udp, p.dport, unmap(p.dst))
		if f == nil {
			return Result{} // not ours (e.g. a stray connection): leave it
		}
		f.last.Store(now)
		writeAddrs(b, &p, p.dst, p.src)
		writePorts(b, &p, f.remote.Port(), p.dport)
		if !udp && p.flags&(tcpFIN|tcpRST) != 0 {
			n.noteClose(f, p.flags)
		}
		return Result{Inbound: true, Modified: true}
	}

	if isSpecial(p.dst) {
		return Result{}
	}
	if udp && !n.hooks.InterceptUDP {
		return Result{}
	}

	key := flowKey{udp: udp, port: p.sport, peer: unmap(p.dst)}
	f := n.lookup(udp, p.sport, unmap(p.dst))
	isSYN := !udp && p.flags&tcpSYN != 0 && p.flags&tcpACK == 0
	if f != nil && (isSYN && f.remote.Port() != p.dport || f.remote.Port() != p.dport && udp) {
		// Port reused for a new destination.
		n.drop(key, f)
		f = nil
	}
	if f == nil {
		if !udp && !isSYN {
			return Result{} // connection predates SentinelProxy
		}
		if udp && p.dport == 53 && n.hooks.AnswerDNS != nil {
			if resp, ok := n.hooks.AnswerDNS(p.udpPayload(b)); ok {
				n.faked.Add(1)
				return Result{Drop: true, Inject: buildUDPReply(b, p, resp)}
			}
		}
		f = n.newFlow(key, p)
	}
	f.last.Store(now)
	if f.self || !f.redirect {
		if f.bypass != nil {
			f.bypass.AddUp(p.payload)
			if !udp && p.flags&(tcpFIN|tcpRST) != 0 {
				n.noteClose(f, p.flags)
			}
		}
		return Result{}
	}
	if !udp && p.flags&(tcpFIN|tcpRST) != 0 {
		n.noteClose(f, p.flags)
	}
	relay := n.relayTCP
	if udp {
		relay = n.relayUDP
	}
	writeAddrs(b, &p, p.dst, p.src)
	writePorts(b, &p, p.sport, relay)
	return Result{Inbound: true, Modified: true}
}

func (n *nat) newFlow(key flowKey, p packet) *flow {
	f := &flow{local: netip.AddrPortFrom(unmap(p.src), p.sport), remote: netip.AddrPortFrom(unmap(p.dst), p.dport)}
	pid, ok := n.hooks.OwnerPID(key.udp, f.local)
	switch {
	case ok && pid == n.hooks.SelfPID:
		f.self = true
	default:
		if ok {
			f.app = n.hooks.App(pid)
		}
		network := "tcp"
		if key.udp {
			network = "udp"
		}
		v := n.hooks.Classify(engine.Flow{Network: network, Inbound: "intercept", Src: f.local, Dst: f.remote, App: f.app})
		f.redirect, f.bypass = v.Redirect, v.Bypass
	}
	if f.redirect {
		n.redirected.Add(1)
	} else if !f.self {
		n.bypassed.Add(1)
	}
	n.mu.Lock()
	n.flows[key] = f
	n.mu.Unlock()
	return f
}

func (n *nat) lookup(udp bool, port uint16, peer netip.Addr) *flow {
	n.mu.RLock()
	f := n.flows[flowKey{udp: udp, port: port, peer: peer}]
	n.mu.RUnlock()
	return f
}

// relayFlow is used by the relays: the accepted peer is (R, lp).
func (n *nat) relayFlow(udp bool, peer netip.AddrPort) *flow {
	f := n.lookup(udp, peer.Port(), unmap(peer.Addr()))
	if f == nil || !f.redirect {
		return nil
	}
	return f
}

func (n *nat) drop(key flowKey, f *flow) {
	n.mu.Lock()
	if n.flows[key] == f {
		delete(n.flows, key)
	}
	n.mu.Unlock()
	if f.bypass != nil && n.hooks.FinishBypass != nil {
		n.hooks.FinishBypass(f.bypass)
	}
}

func (n *nat) noteClose(f *flow, flags uint8) {
	if flags&tcpRST != 0 || f.fins.Add(1) >= 2 {
		f.closedAt.CompareAndSwap(0, time.Now().UnixNano())
	}
}

// inboundBypass counts download bytes of bypassed flows (sniffed packets).
func (n *nat) inboundBypass(b []byte) {
	p, ok := parsePacket(b)
	if !ok || p.proto != protoTCP {
		return
	}
	f := n.lookup(false, p.dport, unmap(p.src))
	if f == nil || f.bypass == nil {
		return
	}
	f.bypass.AddDown(p.payload)
	if p.flags&(tcpFIN|tcpRST) != 0 {
		n.noteClose(f, p.flags)
	}
}

// gc expires closed and idle flows.
func (n *nat) gc() {
	now := time.Now().UnixNano()
	var dead []struct {
		k flowKey
		f *flow
	}
	n.mu.RLock()
	for k, f := range n.flows {
		idle := time.Duration(now - f.last.Load())
		closed := f.closedAt.Load()
		switch {
		case closed != 0 && time.Duration(now-closed) > 30*time.Second:
		case k.udp && idle > 2*time.Minute:
		case !k.udp && idle > 2*time.Hour:
		default:
			continue
		}
		dead = append(dead, struct {
			k flowKey
			f *flow
		}{k, f})
	}
	n.mu.RUnlock()
	for _, d := range dead {
		n.drop(d.k, d.f)
	}
}

func (n *nat) size() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.flows)
}
