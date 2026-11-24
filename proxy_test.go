package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

func TestParsePrefixes(t *testing.T) {
	got, err := parsePrefixes([]string{"10.0.0.0/8", "192.0.2.10", "2001:db8::/32", "10.1.2.3/16"})
	if err != nil {
		t.Fatal(err)
	}
	want := "[10.0.0.0/8 192.0.2.10/32 2001:db8::/32 10.1.0.0/16]"
	if fmt.Sprint(got) != want {
		t.Errorf("got %v, want %s", got, want)
	}
	if _, err := parsePrefixes([]string{"10.0.0.0/8", "proxy.example"}); err == nil {
		t.Error("hostname accepted")
	}
}

// serveRemoteAddr serves r.RemoteAddr on a listener from listen.
func serveRemoteAddr(t *testing.T, trusted string) net.Addr {
	t.Helper()
	ln, err := listen("127.0.0.1:0", true, []netip.Prefix{netip.MustParsePrefix(trusted)})
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, r.RemoteAddr) //nolint:gosec // G705: plain-text test response, not rendered.
		}),
	}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { hs.Close() })
	return ln.Addr()
}

// get sends a GET over a new connection, preceded by a PROXY v2 header
// claiming to come from 192.0.2.1:4711 if withHeader is set.
func get(t *testing.T, addr net.Addr, withHeader bool) (string, error) {
	t.Helper()
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if withHeader {
		h := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 4711}, addr)
		if _, err := h.WriteTo(conn); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var b strings.Builder
	_, err = bufio.NewReader(resp.Body).WriteTo(&b)
	return b.String(), err
}

func TestListenProxyProtocol(t *testing.T) {
	t.Run("trusted proxy", func(t *testing.T) {
		addr := serveRemoteAddr(t, "127.0.0.1/32")
		got, err := get(t, addr, true)
		if err != nil || got != "192.0.2.1:4711" {
			t.Fatalf("RemoteAddr = %q, %v; want the PROXY header's source", got, err)
		}
		if _, err := get(t, addr, false); err == nil {
			t.Fatal("trusted peer without PROXY header was served")
		}
	})
	t.Run("untrusted peer", func(t *testing.T) {
		addr := serveRemoteAddr(t, "10.0.0.0/8")
		if got, err := get(t, addr, true); err == nil {
			t.Fatalf("PROXY header from untrusted peer accepted: RemoteAddr = %q", got)
		}
		got, err := get(t, addr, false)
		if err != nil || !strings.HasPrefix(got, "127.0.0.1:") {
			t.Fatalf("direct connection: RemoteAddr = %q, %v", got, err)
		}
	})
}
