//go:build linux

package procinfo

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestLookupOwnSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	app, ok := LookupTCP(local)
	if !ok || app.PID != uint32(os.Getpid()) {
		t.Fatalf("got %+v %v", app, ok)
	}
	exe, _ := os.Executable()
	if app.Name != filepath.Base(exe) {
		t.Fatalf("name %q want %q", app.Name, filepath.Base(exe))
	}
	if _, ok := LookupTCP(netip.MustParseAddrPort("127.0.0.1:1")); ok {
		t.Fatal("unexpected owner for unused port")
	}
}
