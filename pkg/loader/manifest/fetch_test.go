package manifest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

var (
	fixture     = []byte("\x00asm-fake-plugin-bytes")
	fixtureHash = HashBytes(fixture)
)

func TestHashBytes(t *testing.T) {
	if got := HashBytes([]byte("test")); got != goodHash {
		t.Fatalf("HashBytes = %q, want %q", got, goodHash)
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name    string
		plugin  Plugin
		data    []byte
		wantErr string
	}{
		{
			name:   "hash match",
			plugin: Plugin{Name: "p", Source: "/p.wasm", SHA256: fixtureHash},
			data:   fixture,
		},
		{
			name:   "hash and size match",
			plugin: Plugin{Name: "p", Source: "/p.wasm", SHA256: fixtureHash, Size: int64(len(fixture))},
			data:   fixture,
		},
		{
			name:    "hash mismatch",
			plugin:  Plugin{Name: "p", Source: "/p.wasm", SHA256: goodHash},
			data:    fixture,
			wantErr: "sha256 mismatch: manifest pins " + goodHash + ", got " + fixtureHash + " (source /p.wasm)",
		},
		{
			name:    "size mismatch",
			plugin:  Plugin{Name: "p", Source: "/p.wasm", SHA256: fixtureHash, Size: 3},
			data:    fixture,
			wantErr: "size mismatch: manifest pins 3 bytes",
		},
		{
			name:   "insecure skips hash",
			plugin: Plugin{Name: "p", Source: "/p.wasm", SHA256: goodHash, InsecureSkipVerify: true},
			data:   fixture,
		},
		{
			name:    "insecure still checks size",
			plugin:  Plugin{Name: "p", Source: "/p.wasm", InsecureSkipVerify: true, Size: 3},
			data:    fixture,
			wantErr: "size mismatch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.plugin.Verify(tt.data)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Verify: unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Verify = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestFetchFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.wasm")
	if err := os.WriteFile(path, fixture, 0o644); err != nil {
		t.Fatal(err)
	}

	p := Plugin{Name: "p", Source: path, SHA256: fixtureHash}
	data, err := p.Fetch(context.Background(), "")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(data) != string(fixture) {
		t.Fatalf("Fetch = %q, want fixture", data)
	}

	bad := Plugin{Name: "p", Source: path, SHA256: goodHash}
	if _, err := bad.Fetch(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("Fetch with wrong hash = %v, want sha256 mismatch", err)
	}

	missing := Plugin{Name: "p", Source: filepath.Join(dir, "nope.wasm"), SHA256: fixtureHash}
	if _, err := missing.Fetch(context.Background(), ""); err == nil {
		t.Fatal("Fetch of missing file should error")
	}
}

// newFixtureServer serves *payload at every path and counts requests.
func newFixtureServer(t *testing.T, payload *[]byte, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write(*payload)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchURLCache(t *testing.T) {
	payload := fixture
	var hits atomic.Int64
	srv := newFixtureServer(t, &payload, &hits)
	cacheDir := filepath.Join(t.TempDir(), "cache")

	p := Plugin{Name: "p", Source: srv.URL + "/p.wasm", SHA256: fixtureHash}

	// First fetch downloads and populates the cache.
	data, err := p.Fetch(context.Background(), cacheDir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(data) != string(fixture) || hits.Load() != 1 {
		t.Fatalf("first fetch: data %q, hits %d", data, hits.Load())
	}
	cached := cachePath(cacheDir, fixtureHash)
	if info, err := os.Stat(cached); err != nil {
		t.Fatalf("cache file: %v", err)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("cache file mode = %o, want 600", perm)
	}
	if entries, _ := os.ReadDir(cacheDir); len(entries) != 1 {
		t.Errorf("cache dir should contain exactly the cache file (no leftover temp files), got %v", entries)
	}

	// Second fetch is served from cache: no new request.
	if _, err := p.Fetch(context.Background(), cacheDir); err != nil {
		t.Fatalf("cached Fetch: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("cache hit still made a request (hits = %d)", hits.Load())
	}

	// Corrupt the cache: fetch must detect it, delete it, and refetch.
	if err := os.WriteFile(cached, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err = p.Fetch(context.Background(), cacheDir)
	if err != nil {
		t.Fatalf("Fetch after corruption: %v", err)
	}
	if string(data) != string(fixture) {
		t.Fatalf("Fetch after corruption = %q", data)
	}
	if hits.Load() != 2 {
		t.Fatalf("corrupted cache should force a refetch (hits = %d)", hits.Load())
	}
	if got, _ := os.ReadFile(cached); string(got) != string(fixture) {
		t.Fatalf("cache not rewritten after corruption: %q", got)
	}
}

func TestFetchURLHashMismatch(t *testing.T) {
	payload := []byte("not what was pinned")
	var hits atomic.Int64
	srv := newFixtureServer(t, &payload, &hits)
	cacheDir := filepath.Join(t.TempDir(), "cache")

	p := Plugin{Name: "p", Source: srv.URL + "/p.wasm", SHA256: fixtureHash}
	_, err := p.Fetch(context.Background(), cacheDir)
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("Fetch = %v, want sha256 mismatch", err)
	}
	for _, want := range []string{fixtureHash, HashBytes(payload), srv.URL} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
	// Unverified bytes must never be cached.
	if _, statErr := os.Stat(cachePath(cacheDir, fixtureHash)); !os.IsNotExist(statErr) {
		t.Fatalf("mismatching download must not be cached: %v", statErr)
	}
}

func TestFetchURLSizeCap(t *testing.T) {
	payload := fixture
	var hits atomic.Int64
	srv := newFixtureServer(t, &payload, &hits)

	// Pinned size smaller than the response: capped and rejected.
	p := Plugin{Name: "p", Source: srv.URL + "/p.wasm", SHA256: fixtureHash, Size: 4}
	if _, err := p.Fetch(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "exceeds 4 byte limit") {
		t.Fatalf("Fetch = %v, want size cap error", err)
	}

	// Pinned size larger than the response: size mismatch.
	p = Plugin{Name: "p", Source: srv.URL + "/p.wasm", SHA256: fixtureHash, Size: int64(len(fixture) + 10)}
	if _, err := p.Fetch(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("Fetch = %v, want size mismatch", err)
	}
}

func TestFetchURLHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	p := Plugin{Name: "p", Source: srv.URL + "/p.wasm", SHA256: fixtureHash}
	if _, err := p.Fetch(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("Fetch = %v, want HTTP 404 error", err)
	}
}

func TestFetchSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.wasm")
	if err := os.WriteFile(path, fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := FetchSource(context.Background(), path, 0)
	if err != nil || string(data) != string(fixture) {
		t.Fatalf("FetchSource file = %q, %v", data, err)
	}
	if _, err := FetchSource(context.Background(), path, 4); err == nil {
		t.Fatal("FetchSource should enforce the size cap on files")
	}

	payload := fixture
	var hits atomic.Int64
	srv := newFixtureServer(t, &payload, &hits)
	data, err = FetchSource(context.Background(), srv.URL+"/p.wasm", 0)
	if err != nil || string(data) != string(fixture) {
		t.Fatalf("FetchSource url = %q, %v", data, err)
	}
}

func TestCacheDir(t *testing.T) {
	t.Setenv(CacheDirEnvVar, "/tmp/custom-cache")
	if dir, err := CacheDir(); err != nil || dir != "/tmp/custom-cache" {
		t.Fatalf("CacheDir = %q, %v", dir, err)
	}
	t.Setenv(CacheDirEnvVar, "")
	dir, err := CacheDir()
	if err != nil {
		t.Skipf("no user cache dir on this system: %v", err)
	}
	if filepath.Base(dir) != "caddy-wit" {
		t.Fatalf("CacheDir = %q, want .../caddy-wit", dir)
	}
}
