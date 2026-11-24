package server

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

type clientIPKey struct{}

// clientIPFrom returns the client address stored by withClientIP.
func clientIPFrom(ctx context.Context) netip.Addr {
	a, _ := ctx.Value(clientIPKey{}).(netip.Addr)
	return a
}

// withClientIP stores the request's client address in its context.
func (s *Server) withClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), clientIPKey{}, s.clientIP(r))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// clientIP returns the address of the client that sent r.
//
// If the connection comes from a trusted proxy, X-Forwarded-For is walked
// from the right, skipping trusted proxies, and the first untrusted address
// is the client. Entries left of it were supplied by the client and are
// ignored, so a client cannot spoof its address by sending the header itself.
// A malformed entry stops the walk at the last trusted hop.
func (s *Server) clientIP(r *http.Request) netip.Addr {
	client := parseAddr(r.RemoteAddr)
	if !s.trusted(client) {
		return client
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	for _, hop := range slices.Backward(hops) {
		a := parseAddr(strings.TrimSpace(hop))
		if !a.IsValid() {
			break
		}
		client = a
		if !s.trusted(client) {
			break
		}
	}
	return client
}

func (s *Server) trusted(a netip.Addr) bool {
	return a.IsValid() && slices.ContainsFunc(s.trustedProxies, func(p netip.Prefix) bool { return p.Contains(a) })
}

// parseAddr parses "ip" or "ip:port", unmapping IPv4-mapped IPv6 addresses.
// It returns the zero Addr if s is neither.
func parseAddr(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}

// clientNetwork is the unit challenges are limited by: a single IPv4 address
// or an IPv6 /64, since one IPv6 host usually controls its whole /64.
func clientNetwork(a netip.Addr) netip.Prefix {
	if !a.IsValid() {
		return netip.Prefix{}
	}
	bits := 32
	if a.Is6() {
		bits = 64
	}
	p, _ := a.Prefix(bits)
	return p
}
