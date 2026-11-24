package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
)

// writeKeyPair writes a self-signed certificate for 127.0.0.1 with the given
// serial and its key, returning the certificate.
func writeKeyPair(t *testing.T, certFile, keyFile string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "approle-courier"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeKeyPair(t, certFile, keyFile, 1)

	r, err := newCertReloader(certFile, keyFile, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }
	serial := func() int64 {
		t.Helper()
		c, err := r.getCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf.SerialNumber.Int64()
	}
	if got := serial(); got != 1 {
		t.Fatalf("serial = %d, want 1", got)
	}

	// A renewed certificate is picked up after the check interval.
	renewed := writeKeyPair(t, certFile, keyFile, 2)
	if got := serial(); got != 1 {
		t.Errorf("before check interval: serial = %d, want 1", got)
	}
	now = now.Add(certCheckInterval)
	if got := serial(); got != 2 {
		t.Errorf("after check interval: serial = %d, want 2", got)
	}
	if !r.expiry().Equal(renewed.NotAfter) {
		t.Errorf("expiry = %v, want %v", r.expiry(), renewed.NotAfter)
	}

	// A certificate whose key is not written yet keeps the previous one.
	other := filepath.Join(dir, "other")
	writeKeyPair(t, certFile, other+"-key.pem", 3)
	now = now.Add(certCheckInterval)
	if got := serial(); got != 2 {
		t.Errorf("mismatched key pair: serial = %d, want the previous 2", got)
	}

	if _, err := newCertReloader(filepath.Join(dir, "missing.pem"), keyFile, nil); err == nil {
		t.Error("missing certificate accepted")
	}
}

// TestTLSBehindProxyProtocol checks the layering of the API listener: a
// PROXY header, then the TLS handshake, then HTTP.
func TestTLSBehindProxyProtocol(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	cert := writeKeyPair(t, certFile, keyFile, 1)
	tlsConfig, err := newTLSConfig(listenConfig{TLSCert: certFile, TLSKey: keyFile}, prometheus.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	ln, err := listen("127.0.0.1:0", true, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, r.RemoteAddr) //nolint:gosec // G705: plain-text test response, not rendered.
		}),
	}
	go func() { _ = hs.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { hs.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	header := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 4711}, ln.Addr())
	if _, err := header.WriteTo(conn); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	tc := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	if _, err := fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "192.0.2.1:4711" {
		t.Errorf("RemoteAddr over TLS = %q, want the PROXY header's source", body)
	}
}

func TestNewTLSConfigRequiresBoth(t *testing.T) {
	for _, cfg := range []listenConfig{{TLSCert: "cert.pem"}, {TLSKey: "key.pem"}} {
		if _, err := newTLSConfig(cfg, prometheus.NewRegistry(), nil); err == nil {
			t.Errorf("%+v: accepted", cfg)
		}
	}
	if c, err := newTLSConfig(listenConfig{}, prometheus.NewRegistry(), nil); c != nil || err != nil {
		t.Errorf("no TLS: config = %v, err = %v", c, err)
	}
}
