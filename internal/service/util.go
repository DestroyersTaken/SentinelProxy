package service

import "net/netip"

func parseIP(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	return ip.Unmap(), err
}
