package intercept

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/DestroyersTaken/SentinelProxy/internal/engine"
	"github.com/DestroyersTaken/SentinelProxy/internal/match"
)

func ipv4Packet(proto uint8, src, dst netip.AddrPort, flags uint8, payload []byte) []byte {
	l4 := 20
	if proto == protoUDP {
		l4 = 8
	}
	b := make([]byte, 20+l4+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64
	b[9] = proto
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	binary.BigEndian.PutUint16(b[20:], src.Port())
	binary.BigEndian.PutUint16(b[22:], dst.Port())
	if proto == protoTCP {
		b[32] = 5 << 4
		b[33] = flags
	} else {
		binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	}
	copy(b[20+l4:], payload)
	return b
}

func ipv6Packet(src, dst netip.AddrPort, flags uint8) []byte {
	b := make([]byte, 40+20)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], 20)
	b[6] = protoTCP
	b[7] = 64
	s, d := src.Addr().As16(), dst.Addr().As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	binary.BigEndian.PutUint16(b[40:], src.Port())
	binary.BigEndian.PutUint16(b[42:], dst.Port())
	b[52] = 5 << 4
	b[53] = flags
	return b
}

func testNAT(redirect bool, ownerPID uint32) (*nat, *[]engine.Flow) {
	var seen []engine.Flow
	n := newNAT(Hooks{
		Classify: func(f engine.Flow) engine.Verdict {
			seen = append(seen, f)
			return engine.Verdict{Redirect: redirect}
		},
		OwnerPID:     func(bool, netip.AddrPort) (uint32, bool) { return ownerPID, true },
		App:          func(pid uint32) match.AppInfo { return match.AppInfo{Name: "app.exe", PID: pid} },
		SelfPID:      99,
		InterceptUDP: true,
	}, 40000, 40001)
	return n, &seen
}

func TestReflectTCP(t *testing.T) {
	n, seen := testNAT(true, 1234)
	L := netip.MustParseAddrPort("192.168.1.10:51000")
	R := netip.MustParseAddrPort("93.184.216.34:443")
	syn := ipv4Packet(protoTCP, L, R, tcpSYN, nil)
	res := n.outbound(syn)
	if !res.Inbound || !res.Modified {
		t.Fatalf("SYN not redirected: %+v", res)
	}
	p, _ := parsePacket(syn)
	if p.src != R.Addr() || p.dst != L.Addr() || p.sport != L.Port() || p.dport != 40000 {
		t.Fatalf("bad reflect %+v", p)
	}
	if len(*seen) != 1 || (*seen)[0].App.Name != "app.exe" || (*seen)[0].Dst != R {
		t.Fatalf("classify got %+v", *seen)
	}
	// The relay accepts a connection from R:lp and finds the original destination.
	f := n.relayFlow(false, netip.AddrPortFrom(R.Addr(), L.Port()))
	if f == nil || f.remote != R || f.local != L {
		t.Fatalf("relay lookup %+v", f)
	}
	// Relay reply L:relay -> R:lp becomes R:rp -> L:lp.
	reply := ipv4Packet(protoTCP, netip.AddrPortFrom(L.Addr(), 40000), netip.AddrPortFrom(R.Addr(), L.Port()), tcpSYN|tcpACK, nil)
	res = n.outbound(reply)
	p, _ = parsePacket(reply)
	if !res.Inbound || p.src != R.Addr() || p.sport != R.Port() || p.dst != L.Addr() || p.dport != L.Port() {
		t.Fatalf("bad reply rewrite %+v %+v", res, p)
	}
	// Data packets of the same flow keep being redirected without re-classifying.
	data := ipv4Packet(protoTCP, L, R, tcpACK, []byte("hello"))
	if res := n.outbound(data); !res.Inbound {
		t.Fatal("data not redirected")
	}
	if len(*seen) != 1 {
		t.Fatal("classified twice")
	}
	// A non-SYN packet of an unknown flow passes untouched.
	other := ipv4Packet(protoTCP, netip.MustParseAddrPort("192.168.1.10:52000"), R, tcpACK, nil)
	if res := n.outbound(other); res.Inbound || res.Modified {
		t.Fatal("pre-existing connection must pass")
	}
}

func TestSelfAndBypass(t *testing.T) {
	n, seen := testNAT(true, 99)
	L := netip.MustParseAddrPort("10.0.0.5:50000")
	R := netip.MustParseAddrPort("1.1.1.1:1080")
	if res := n.outbound(ipv4Packet(protoTCP, L, R, tcpSYN, nil)); res.Inbound {
		t.Fatal("own traffic must never be redirected")
	}
	if len(*seen) != 0 {
		t.Fatal("own traffic must not be classified")
	}
	n2, _ := testNAT(false, 1)
	if res := n2.outbound(ipv4Packet(protoTCP, L, R, tcpSYN, nil)); res.Inbound {
		t.Fatal("bypass verdict must pass")
	}
	if res := n2.outbound(ipv4Packet(protoUDP, L, netip.MustParseAddrPort("224.0.0.251:5353"), 0, []byte{1})); res.Inbound {
		t.Fatal("multicast must pass")
	}
}

func TestReflectIPv6AndUDP(t *testing.T) {
	n, _ := testNAT(true, 5)
	L := netip.MustParseAddrPort("[2001:db8::10]:50001")
	R := netip.MustParseAddrPort("[2606:4700::1111]:443")
	pkt := ipv6Packet(L, R, tcpSYN)
	if res := n.outbound(pkt); !res.Inbound {
		t.Fatal("v6 not redirected")
	}
	p, _ := parsePacket(pkt)
	if p.src != R.Addr() || p.dport != 40000 {
		t.Fatalf("%+v", p)
	}
	uL := netip.MustParseAddrPort("192.168.0.2:60000")
	uR := netip.MustParseAddrPort("8.8.4.4:443")
	u := ipv4Packet(protoUDP, uL, uR, 0, []byte("quic"))
	if res := n.outbound(u); !res.Inbound {
		t.Fatal("udp not redirected")
	}
	p, _ = parsePacket(u)
	if p.dport != 40001 || p.src != uR.Addr() {
		t.Fatalf("%+v", p)
	}
	if f := n.relayFlow(true, netip.AddrPortFrom(uR.Addr(), uL.Port())); f == nil || f.remote != uR {
		t.Fatal("udp relay lookup failed")
	}
}

func TestFakeDNSInjection(t *testing.T) {
	n, _ := testNAT(true, 5)
	n.hooks.AnswerDNS = func(q []byte) ([]byte, bool) { return append([]byte("ANSWER:"), q...), true }
	L := netip.MustParseAddrPort("192.168.0.2:53000")
	R := netip.MustParseAddrPort("192.168.0.1:53")
	q := ipv4Packet(protoUDP, L, R, 0, []byte("query"))
	res := n.outbound(q)
	if !res.Drop || res.Inject == nil {
		t.Fatalf("%+v", res)
	}
	p, ok := parsePacket(res.Inject)
	if !ok || p.src != R.Addr() || p.sport != 53 || p.dst != L.Addr() || p.dport != L.Port() || string(p.udpPayload(res.Inject)) != "ANSWER:query" {
		t.Fatalf("bad injected answer %+v %q", p, res.Inject)
	}
}
