package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// certCheckInterval is how often the certificate files are checked for
// changes, at most.
const certCheckInterval = 10 * time.Second

// certReloader serves a certificate from files and reloads them when they
// change, so renewed certificates are picked up without a restart. If a
// reload fails, e.g. because the certificate was replaced but the matching
// key not yet, the previous certificate is served and the reload retried.
type certReloader struct {
	certFile, keyFile string
	log               *slog.Logger
	now               func() time.Time

	mu        sync.Mutex
	cert      *tls.Certificate
	stamps    [2]fileStamp
	lastCheck time.Time
}

// fileStamp identifies a version of a file.
type fileStamp struct {
	mod  time.Time
	size int64
}

func newCertReloader(certFile, keyFile string, log *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, log: log, now: time.Now}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// tlsConfig returns a server TLS configuration serving r's certificate.
func (r *certReloader) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: r.getCertificate,
	}
}

func (r *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if now := r.now(); now.Sub(r.lastCheck) >= certCheckInterval {
		r.lastCheck = now
		if r.changed() {
			if err := r.reload(); err != nil {
				r.log.Error("reloading TLS certificate failed; serving the previous one", "err", err)
			} else {
				r.log.Info("reloaded TLS certificate", "not_after", r.cert.Leaf.NotAfter)
			}
		}
	}
	return r.cert, nil
}

// expiry returns when the served certificate expires.
func (r *certReloader) expiry() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cert.Leaf.NotAfter
}

// changed reports whether either file differs from the loaded version. A
// file that cannot be read counts as changed, so the reload reports why.
func (r *certReloader) changed() bool {
	stamps, err := r.stat()
	return err != nil || stamps != r.stamps
}

// reload loads the key pair. r.mu must be held, except during construction.
func (r *certReloader) reload() error {
	stamps, err := r.stat()
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS key pair: %w", err)
	}
	if cert.Leaf == nil {
		return errors.New("load TLS key pair: no leaf certificate")
	}
	r.cert, r.stamps = &cert, stamps
	return nil
}

func (r *certReloader) stat() ([2]fileStamp, error) {
	var stamps [2]fileStamp
	for i, name := range []string{r.certFile, r.keyFile} {
		fi, err := os.Stat(name)
		if err != nil {
			return stamps, err
		}
		stamps[i] = fileStamp{mod: fi.ModTime(), size: fi.Size()}
	}
	return stamps, nil
}
