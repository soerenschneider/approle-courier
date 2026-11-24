package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestClientIP(t *testing.T) {
	s := &Server{trustedProxies: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("2001:db8::1/128"),
	}}
	tests := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{name: "direct", remote: "198.51.100.7:4711", want: "198.51.100.7"},
		{name: "direct ignores header", remote: "198.51.100.7:4711", xff: []string{"192.0.2.1"}, want: "198.51.100.7"},
		{name: "via proxy", remote: "10.0.0.5:4711", xff: []string{"192.0.2.1"}, want: "192.0.2.1"},
		{name: "proxy chain", remote: "10.0.0.5:4711", xff: []string{"192.0.2.1, 10.0.0.9"}, want: "192.0.2.1"},
		{name: "spoofed entry left of client", remote: "10.0.0.5:4711", xff: []string{"203.0.113.66, 192.0.2.1"}, want: "192.0.2.1"},
		{name: "multiple headers", remote: "10.0.0.5:4711", xff: []string{"203.0.113.66", "192.0.2.1"}, want: "192.0.2.1"},
		{name: "only proxies", remote: "10.0.0.5:4711", xff: []string{"10.0.0.8"}, want: "10.0.0.8"},
		{name: "proxy without header", remote: "10.0.0.5:4711", want: "10.0.0.5"},
		{name: "malformed stops at last trusted hop", remote: "10.0.0.5:4711", xff: []string{"192.0.2.1, garbage"}, want: "10.0.0.5"},
		{name: "ipv6 proxy", remote: "[2001:db8::1]:4711", xff: []string{"2001:db8:ffff::5"}, want: "2001:db8:ffff::5"},
		{name: "ipv4-mapped peer", remote: "[::ffff:10.0.0.5]:4711", xff: []string{"192.0.2.1"}, want: "192.0.2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := s.clientIP(r); got != netip.MustParseAddr(tt.want) {
				t.Errorf("clientIP = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClientNetwork(t *testing.T) {
	for addr, want := range map[string]string{
		"192.0.2.1":            "192.0.2.1/32",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
	} {
		if got := clientNetwork(netip.MustParseAddr(addr)); got != netip.MustParsePrefix(want) {
			t.Errorf("clientNetwork(%s) = %s, want %s", addr, got, want)
		}
	}
}

func TestClientLimiter(t *testing.T) {
	l := newKeyedLimiter[netip.Prefix](1, 2)
	now := time.Now()
	a := netip.MustParsePrefix("192.0.2.1/32")
	b := netip.MustParsePrefix("192.0.2.2/32")

	for i := range 2 {
		if ok, _ := l.allow(a, now); !ok {
			t.Fatalf("request %d within burst not allowed", i)
		}
	}
	if ok, wait := l.allow(a, now); ok || wait != time.Second {
		t.Fatalf("request over burst: allowed = %v, wait = %s; want denied, 1s", ok, wait)
	}
	if ok, _ := l.allow(b, now); !ok {
		t.Fatal("other client limited")
	}
	if ok, _ := l.allow(a, now.Add(time.Second)); !ok {
		t.Fatal("token not refilled after 1s")
	}

	// Idle limiters are swept once their bucket is full again.
	l.allow(b, now.Add(time.Hour))
	if len(l.limiters) != 1 {
		t.Errorf("limiters after sweep = %d, want 1", len(l.limiters))
	}
}
