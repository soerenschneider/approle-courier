package main

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/pires/go-proxyproto"
)

// parsePrefixes parses IP addresses and CIDR prefixes, e.g. "10.0.0.0/8" or
// "192.0.2.10".
func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range list {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("invalid address or prefix %q", f)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// listen opens a TCP listener on addr. With proxyProtocol, connections from
// trusted addresses must start with a PROXY protocol (v1 or v2) header, whose
// source address then becomes the connection's remote address; a header from
// any other address is rejected, so clients cannot spoof their address.
func listen(addr string, proxyProtocol bool, trusted []netip.Prefix) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil || !proxyProtocol {
		return ln, err
	}
	return &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: 5 * time.Second,
		ConnPolicy: func(o proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			ap, err := netip.ParseAddrPort(o.Upstream.String())
			if err == nil && slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(ap.Addr().Unmap()) }) {
				return proxyproto.REQUIRE, nil
			}
			return proxyproto.REJECT, nil
		},
	}, nil
}
