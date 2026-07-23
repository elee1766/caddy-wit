// CLI-surface tests: argv dispatch, flag parsing, exit codes, and
// stdout/stderr routing. The subcommand logic itself is tested in
// github.com/elee1766/caddy-wit/pkg/manifestcli.
package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/elee1766/caddy-wit/pkg/loader/manifest"
)

var (
	fixture     = []byte("\x00asm-fake-plugin-bytes")
	fixtureHash = manifest.HashBytes(fixture)
)

// runCLI invokes run and returns exit code, stdout, stderr.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// newServer serves *payload on every path.
func newServer(t *testing.T, payload *[]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(*payload)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func mustLoadEditable(t *testing.T, path string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.LoadEditable(path)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestUsageAndUnknownCommands(t *testing.T) {
	if code, _, stderr := runCLI(t); code != 2 || !strings.Contains(stderr, "Usage") {
		t.Fatalf("no args: code %d, stderr %q", code, stderr)
	}
	if code, stdout, _ := runCLI(t, "help"); code != 0 || !strings.Contains(stdout, "manifest init") {
		t.Fatalf("help: code %d, stdout %q", code, stdout)
	}
	if code, _, _ := runCLI(t, "bogus"); code != 2 {
		t.Fatal("unknown command should exit 2")
	}
	if code, _, _ := runCLI(t, "manifest", "bogus"); code != 2 {
		t.Fatal("unknown subcommand should exit 2")
	}
	if code, _, stderr := runCLI(t, "manifest"); code != 2 || !strings.Contains(stderr, "Usage") {
		t.Fatalf("bare manifest: code %d, stderr %q", code, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	// Wrong arity per subcommand: exit 1 with a usage message on stderr.
	for _, tt := range [][]string{
		{"manifest", "init"},
		{"manifest", "init", "a", "b"},
		{"manifest", "add", "only-path"},
		{"manifest", "pin"},
		{"manifest", "verify"},
	} {
		code, _, stderr := runCLI(t, tt...)
		if code != 1 || !strings.Contains(stderr, "usage: caddywit manifest") {
			t.Errorf("%v: code %d, stderr %q", tt, code, stderr)
		}
	}
	// Unknown flag on add: exit 1 with the add usage line.
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")
	code, _, stderr := runCLI(t, "manifest", "add", path, "x.wasm", "-bogus")
	if code != 1 || !strings.Contains(stderr, "usage: caddywit manifest add") {
		t.Fatalf("unknown flag: code %d, stderr %q", code, stderr)
	}
}

func TestInitCLI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")

	code, stdout, stderr := runCLI(t, "manifest", "init", path)
	if code != 0 {
		t.Fatalf("init: code %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "wrote empty manifest "+path) {
		t.Fatalf("init stdout: %q", stdout)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"version\": 1,\n  \"plugins\": []\n}\n"
	if string(data) != want {
		t.Fatalf("init wrote %q, want %q", data, want)
	}

	// Refuses to overwrite; the error is prefixed and exits 1.
	code, _, stderr = runCLI(t, "manifest", "init", path)
	if code != 1 || !strings.Contains(stderr, "caddywit: refusing to overwrite") {
		t.Fatalf("re-init: code %d, stderr %q", code, stderr)
	}
}

func TestAddCLIFlags(t *testing.T) {
	payload := fixture
	srv := newServer(t, &payload)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")
	if code, _, stderr := runCLI(t, "manifest", "init", path); code != 0 {
		t.Fatal(stderr)
	}

	// No flags: name defaults to the source basename.
	code, stdout, stderr := runCLI(t, "manifest", "add", path, srv.URL+"/v1/hello.wasm")
	if code != 0 {
		t.Fatalf("add url: code %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, `added "hello"`) || !strings.Contains(stdout, fixtureHash) {
		t.Fatalf("add url stdout: %q", stdout)
	}

	// Flags may trail the positional arguments.
	local := []byte("local plugin bytes")
	if err := os.WriteFile(filepath.Join(dir, "local.wasm"), local, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCLI(t, "manifest", "add", path, "local.wasm", "-name", "dev")
	if code != 0 {
		t.Fatalf("add file: code %d, stderr %q", code, stderr)
	}

	// -permissions is parsed and forwarded; leading-flag placement works.
	code, stdout, stderr = runCLI(t, "manifest", "add", path, "-permissions", "http,tcp", srv.URL+"/dns.wasm")
	if code != 0 {
		t.Fatalf("add with permissions: code %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "permissions: http,tcp") {
		t.Fatalf("add stdout should report granted permissions: %q", stdout)
	}
	m := mustLoadEditable(t, path)
	if len(m.Plugins) != 3 ||
		m.Plugins[0].Name != "hello" ||
		m.Plugins[1].Name != "dev" || m.Plugins[1].Source != "local.wasm" ||
		!reflect.DeepEqual(m.Plugins[2].Permissions, []string{"http", "tcp"}) {
		t.Fatalf("plugins = %+v", m.Plugins)
	}

	// Bad permission values surface with the caddywit prefix and exit 1.
	code, _, stderr = runCLI(t, "manifest", "add", path, srv.URL+"/bad.wasm", "-permissions", "udp")
	if code != 1 || !strings.Contains(stderr, `caddywit: -permissions: unknown permission "udp"`) {
		t.Fatalf("add with bad permission: code %d, stderr %q", code, stderr)
	}
}

func TestVerifyCLIExitCodesAndStreams(t *testing.T) {
	payload := fixture
	srv := newServer(t, &payload)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")

	local := []byte("local plugin bytes")
	if err := os.WriteFile(filepath.Join(dir, "local.wasm"), local, 0o644); err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		{Name: "hello", Source: srv.URL + "/hello.wasm", SHA256: fixtureHash, Size: int64(len(fixture))},
		{Name: "local", Source: "local.wasm", SHA256: manifest.HashBytes(local)},
	}}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	// All entries intact: exit 0, per-entry report on stdout.
	code, stdout, stderr := runCLI(t, "manifest", "verify", path)
	if code != 0 {
		t.Fatalf("verify: code %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "ok   hello") || !strings.Contains(stdout, "ok   local") {
		t.Fatalf("verify stdout: %q", stdout)
	}

	// Tampered upstream: exit 1; FAIL lines and the summary go to
	// stderr while intact entries still report ok on stdout.
	payload = []byte("tampered bytes")
	code, stdout, stderr = runCLI(t, "manifest", "verify", path)
	if code != 1 {
		t.Fatalf("verify after tamper: code %d", code)
	}
	if !strings.Contains(stderr, "FAIL hello") || !strings.Contains(stderr, "caddywit: manifest verification failed for "+path) {
		t.Fatalf("verify stderr: %q", stderr)
	}
	if !strings.Contains(stdout, "ok   local") {
		t.Fatalf("intact entry should still verify: %q", stdout)
	}

	// A manifest the loader would reject also exits 1 with the
	// caddywit-prefixed error.
	unpinned := filepath.Join(dir, "unpinned.json")
	um := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		{Name: "hello", Source: srv.URL + "/hello.wasm"},
	}}
	if err := um.Save(unpinned); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCLI(t, "manifest", "verify", unpinned)
	if code != 1 || !strings.Contains(stderr, "caddywit: ") || !strings.Contains(stderr, "requires a pinned sha256") {
		t.Fatalf("verify unpinned: code %d, stderr %q", code, stderr)
	}
}

func TestPinCLI(t *testing.T) {
	payload := fixture
	srv := newServer(t, &payload)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")

	m := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		{Name: "hello", Source: srv.URL + "/hello.wasm"},
	}}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCLI(t, "manifest", "pin", path)
	if code != 0 {
		t.Fatalf("pin: code %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, fixtureHash) {
		t.Fatalf("pin stdout: %q", stdout)
	}

	// A failing pin exits 1 with the caddywit prefix.
	bad := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		{Name: "bad", Source: filepath.Join(dir, "missing.wasm")},
	}}
	badPath := filepath.Join(dir, "bad.json")
	if err := bad.Save(badPath); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCLI(t, "manifest", "pin", badPath)
	if code != 1 || !strings.Contains(stderr, "caddywit: manifest not updated") {
		t.Fatalf("pin broken: code %d, stderr %q", code, stderr)
	}
}
