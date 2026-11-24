package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/soerenschneider/approle-courier/internal/server"
)

const testRecipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

// fakeSource serves data, or fails with err, and counts loads.
type fakeSource struct {
	data  string
	err   error
	loads int
}

func (f *fakeSource) Load(context.Context) ([]byte, error) {
	f.loads++
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.data), nil
}

func (f *fakeSource) String() string { return "fake" }

func newTestRegistry(src Source) (*Registry, *time.Time) {
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	r := New(src, 10*time.Second)
	r.now = func() time.Time { return now }
	return r, &now
}

func TestRegistry(t *testing.T) {
	src := &fakeSource{data: `{"node-42":{"age_recipient":"` + testRecipient + `","roles":{"approle":["my-role"]}}}`}
	r, _ := newTestRegistry(src)
	ctx := context.Background()

	rec, err := r.AgeRecipient(ctx, "node-42")
	if err != nil || rec != testRecipient {
		t.Fatalf("AgeRecipient = %q, %v", rec, err)
	}
	if _, err := r.AgeRecipient(ctx, "node-7"); !errors.Is(err, server.ErrUnknownMachine) {
		t.Errorf("unknown machine: err = %v", err)
	}
	for role, want := range map[string]bool{"my-role": true, "other-role": false} {
		if ok, err := r.Authorized(ctx, "node-42", "approle", role); err != nil || ok != want {
			t.Errorf("Authorized(%s) = %v, %v", role, ok, err)
		}
	}
	if ok, err := r.Authorized(ctx, "node-7", "approle", "my-role"); err != nil || ok {
		t.Errorf("Authorized(unknown machine) = %v, %v", ok, err)
	}
	if src.loads != 1 {
		t.Errorf("loads = %d, want 1 (cached)", src.loads)
	}
}

func TestRegistryRefreshAndFailClosed(t *testing.T) {
	src := &fakeSource{data: `{"node-42":{"age_recipient":"` + testRecipient + `"}}`}
	r, now := newTestRegistry(src)
	ctx := context.Background()

	if err := r.Check(ctx); err != nil {
		t.Fatal(err)
	}

	// The machine is removed; the cached document is used until the TTL ends.
	src.data = `{}`
	*now = now.Add(9 * time.Second)
	if _, err := r.AgeRecipient(ctx, "node-42"); err != nil {
		t.Fatalf("within TTL: err = %v", err)
	}
	*now = now.Add(time.Second)
	if _, err := r.AgeRecipient(ctx, "node-42"); !errors.Is(err, server.ErrUnknownMachine) {
		t.Fatalf("after TTL: err = %v, want ErrUnknownMachine", err)
	}

	// A failed load or invalid document is an error, not the stale document.
	*now = now.Add(10 * time.Second)
	src.err = errors.New("vault down")
	if _, err := r.AgeRecipient(ctx, "node-42"); !errors.Is(err, server.ErrRegistryUnavailable) {
		t.Fatalf("load failure: err = %v, want ErrRegistryUnavailable", err)
	}
	src.err, src.data = nil, `{"node-42":{"age_recipient":"not-a-key"}}`
	if err := r.Check(ctx); !errors.Is(err, server.ErrRegistryUnavailable) {
		t.Fatalf("invalid document: err = %v, want ErrRegistryUnavailable", err)
	}
}

func TestRegistryContextCanceled(t *testing.T) {
	r, _ := newTestRegistry(&fakeSource{})
	r.sem <- struct{}{} // simulate a load in progress
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestParseOldLayout(t *testing.T) {
	_, err := parse([]byte(`{"machines":{"node-42":{"age_recipient":"` + testRecipient + `"}}}`))
	if err == nil || !strings.Contains(err.Error(), "old layout") {
		t.Fatalf("err = %v", err)
	}
}

func TestFileSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machines.json")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"node-42":{"age_recipient":"` + testRecipient + `"}}`)
	r, now := newTestRegistry(FileSource{Path: path})
	ctx := context.Background()

	if _, err := r.AgeRecipient(ctx, "node-42"); err != nil {
		t.Fatal(err)
	}
	// Edits are picked up after the TTL, without a restart.
	write(`{}`)
	*now = now.Add(10 * time.Second)
	if _, err := r.AgeRecipient(ctx, "node-42"); !errors.Is(err, server.ErrUnknownMachine) {
		t.Fatalf("after edit: err = %v, want ErrUnknownMachine", err)
	}
	if got := (FileSource{Path: path}).String(); got != "file "+path {
		t.Errorf("String = %q", got)
	}
}

type fakeKVReader struct{ mount, path string }

func (f *fakeKVReader) ReadKV2(_ context.Context, mount, path string) (json.RawMessage, error) {
	f.mount, f.path = mount, path
	return json.RawMessage(`{}`), nil
}

func TestKVSource(t *testing.T) {
	reader := &fakeKVReader{}
	src := KVSource{Reader: reader, Mount: "secret", Path: "approle-courier/registry"}
	b, err := src.Load(context.Background())
	if err != nil || string(b) != `{}` {
		t.Fatalf("Load = %s, %v", b, err)
	}
	if reader.mount != "secret" || reader.path != "approle-courier/registry" {
		t.Errorf("read %s/%s", reader.mount, reader.path)
	}
	if got := src.String(); got != "kv secret/approle-courier/registry" {
		t.Errorf("String = %q", got)
	}
}

func TestRegistryConcurrentLookups(t *testing.T) {
	src := &fakeSource{data: `{"node-42":{"age_recipient":"` + testRecipient + `"}}`}
	r := New(src, time.Minute)
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for range 50 {
		wg.Go(func() {
			if _, err := r.AgeRecipient(context.Background(), "node-42"); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	// Loads happen under sem, so fakeSource's counter needs no lock.
	if src.loads != 1 {
		t.Errorf("loads = %d, want 1: concurrent cache misses must share one load", src.loads)
	}
}

func TestMachinesWithRole(t *testing.T) {
	src := &fakeSource{data: `{
		"vm-1": {"age_recipient":"` + testRecipient + `","roles":{"approle":["vm-1","shared"]}},
		"vm-2": {"age_recipient":"` + testRecipient + `","roles":{"approle":["vm-2","shared"]}}
	}`}
	r, _ := newTestRegistry(src)
	for role, want := range map[string]string{"vm-1": "[vm-1]", "shared": "[vm-1 vm-2]", "none": "[]"} {
		ids, err := r.MachinesWithRole(context.Background(), "approle", role)
		if err != nil || fmt.Sprint(ids) != want {
			t.Errorf("MachinesWithRole(%s) = %v, %v; want %s", role, ids, err, want)
		}
	}
}
