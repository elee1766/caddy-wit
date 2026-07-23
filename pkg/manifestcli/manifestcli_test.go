package manifestcli

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

func mustInit(t *testing.T, path string) {
	t.Helper()
	if err := Init(&bytes.Buffer{}, path); err != nil {
		t.Fatal(err)
	}
}

func TestInit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")

	var out bytes.Buffer
	if err := Init(&out, path); err != nil {
		t.Fatalf("init: %v", err)
	}
	if !strings.Contains(out.String(), "wrote empty manifest "+path) {
		t.Fatalf("init output: %q", out.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"version\": 1,\n  \"plugins\": []\n}\n"
	if string(data) != want {
		t.Fatalf("init wrote %q, want %q", data, want)
	}

	// Refuses to overwrite.
	err = Init(&out, path)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("re-init: %v", err)
	}
}

func TestAdd(t *testing.T) {
	payload := fixture
	srv := newServer(t, &payload)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")
	mustInit(t, path)

	// Add a URL source; name defaults to basename without .wasm.
	var out bytes.Buffer
	if err := Add(&out, path, srv.URL+"/v1/hello.wasm", "", ""); err != nil {
		t.Fatalf("add url: %v", err)
	}
	if !strings.Contains(out.String(), `added "hello"`) || !strings.Contains(out.String(), fixtureHash) {
		t.Fatalf("add url output: %q", out.String())
	}
	m := mustLoadEditable(t, path)
	if len(m.Plugins) != 1 {
		t.Fatalf("plugins = %+v", m.Plugins)
	}
	p := m.Plugins[0]
	if p.Name != "hello" || p.Source != srv.URL+"/v1/hello.wasm" || p.SHA256 != fixtureHash || p.Size != int64(len(fixture)) {
		t.Fatalf("entry = %+v", p)
	}

	// Add a filesystem source relative to the manifest dir, with an
	// explicit name.
	local := []byte("local plugin bytes")
	if err := os.WriteFile(filepath.Join(dir, "local.wasm"), local, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Add(&out, path, "local.wasm", "dev", ""); err != nil {
		t.Fatalf("add file: %v", err)
	}
	m = mustLoadEditable(t, path)
	if len(m.Plugins) != 2 || m.Plugins[1].Name != "dev" || m.Plugins[1].SHA256 != manifest.HashBytes(local) {
		t.Fatalf("plugins = %+v", m.Plugins)
	}
	if m.Plugins[1].Source != "local.wasm" {
		t.Fatalf("relative source rewritten: %q", m.Plugins[1].Source)
	}

	// Duplicate name and duplicate source are rejected.
	if err := Add(&out, path, srv.URL+"/other/hello.wasm", "", ""); err == nil || !strings.Contains(err.Error(), `named "hello"`) {
		t.Fatalf("dup name: %v", err)
	}
	if err := Add(&out, path, "local.wasm", "dev2", ""); err == nil || !strings.Contains(err.Error(), "entry for source") {
		t.Fatalf("dup source: %v", err)
	}

	// Unfetchable source is rejected and nothing is appended.
	if err := Add(&out, path, filepath.Join(dir, "missing.wasm"), "", ""); err == nil {
		t.Fatal("add of missing file should fail")
	}
	if m := mustLoadEditable(t, path); len(m.Plugins) != 2 {
		t.Fatalf("failed add must not append: %+v", m.Plugins)
	}
}

func TestAddPermissions(t *testing.T) {
	payload := fixture
	srv := newServer(t, &payload)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")
	mustInit(t, path)

	// permissions writes the granted list and reports it.
	var out bytes.Buffer
	if err := Add(&out, path, srv.URL+"/dns.wasm", "", "http,tcp"); err != nil {
		t.Fatalf("add with permissions: %v", err)
	}
	if !strings.Contains(out.String(), "permissions: http,tcp") {
		t.Fatalf("add output should report granted permissions: %q", out.String())
	}
	m := mustLoadEditable(t, path)
	if len(m.Plugins) != 1 || !reflect.DeepEqual(m.Plugins[0].Permissions, []string{"http", "tcp"}) {
		t.Fatalf("plugins = %+v", m.Plugins)
	}

	// Entries without permissions stay permission-less and report "none".
	out.Reset()
	if err := Add(&out, path, srv.URL+"/plain.wasm", "", ""); err != nil {
		t.Fatalf("add without permissions: %v", err)
	}
	if !strings.Contains(out.String(), "permissions: none") {
		t.Fatalf("add output should report no permissions: %q", out.String())
	}
	m = mustLoadEditable(t, path)
	if len(m.Plugins) != 2 || m.Plugins[1].Permissions != nil {
		t.Fatalf("plugins = %+v", m.Plugins)
	}

	// Invalid values are rejected (listing the valid ones) and nothing
	// is appended.
	err := Add(&out, path, srv.URL+"/bad.wasm", "", "udp")
	if err == nil || !strings.Contains(err.Error(), `unknown permission "udp"`) || !strings.Contains(err.Error(), `valid permissions: "http", "tcp"`) {
		t.Fatalf("add with bad permission: %v", err)
	}
	err = Add(&out, path, srv.URL+"/bad.wasm", "", "http,http")
	if err == nil || !strings.Contains(err.Error(), `duplicate permission "http"`) {
		t.Fatalf("add with duplicate permission: %v", err)
	}
	if m := mustLoadEditable(t, path); len(m.Plugins) != 2 {
		t.Fatalf("failed add must not append: %+v", m.Plugins)
	}

	// verify reports permissions per entry.
	out.Reset()
	if err := Verify(&out, path); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out.String(), "permissions: http,tcp") || !strings.Contains(out.String(), "permissions: none") {
		t.Fatalf("verify output should report permissions: %q", out.String())
	}
}

func TestPin(t *testing.T) {
	payload := fixture
	srv := newServer(t, &payload)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")

	// Hand-written, unpinned manifest: URL entry with no sha256.
	m := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		{Name: "hello", Source: srv.URL + "/hello.wasm"},
	}}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Pin(&out, path); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if !strings.Contains(out.String(), fixtureHash) {
		t.Fatalf("pin output: %q", out.String())
	}
	got := mustLoadEditable(t, path)
	if got.Plugins[0].SHA256 != fixtureHash || got.Plugins[0].Size != int64(len(fixture)) {
		t.Fatalf("pinned entry = %+v", got.Plugins[0])
	}

	// Upstream bytes change: pin updates the lock.
	payload = []byte("version 2 bytes")
	if err := Pin(&out, path); err != nil {
		t.Fatal(err)
	}
	got = mustLoadEditable(t, path)
	if got.Plugins[0].SHA256 != manifest.HashBytes(payload) || got.Plugins[0].Size != int64(len(payload)) {
		t.Fatalf("re-pinned entry = %+v", got.Plugins[0])
	}
}

func TestPinAllOrNothing(t *testing.T) {
	payload := fixture
	srv := newServer(t, &payload)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")

	m := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		{Name: "good", Source: srv.URL + "/good.wasm"},
		{Name: "bad", Source: filepath.Join(dir, "missing.wasm")},
	}}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	perr := Pin(&bytes.Buffer{}, path)
	if perr == nil || !strings.Contains(perr.Error(), "manifest not updated") {
		t.Fatalf("pin with broken entry: %v", perr)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed pin must not rewrite the manifest")
	}
}

func TestVerify(t *testing.T) {
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
		{Name: "dev", Source: "local.wasm", InsecureSkipVerify: true},
	}}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if err := VerifyStreams(&out, &errOut, path); err != nil {
		t.Fatalf("verify: %v (errOut %q)", err, errOut.String())
	}
	for _, want := range []string{"ok   hello", "ok   local", "skip dev"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("verify output missing %q:\n%s", want, out.String())
		}
	}

	// Upstream changes out from under the pin: verify fails, reporting
	// the mismatching entry but still passing the intact ones.
	payload = []byte("tampered bytes")
	out.Reset()
	errOut.Reset()
	err := VerifyStreams(&out, &errOut, path)
	if err == nil || !strings.Contains(err.Error(), "manifest verification failed for "+path) {
		t.Fatalf("verify after tamper: %v", err)
	}
	if !strings.Contains(errOut.String(), "FAIL hello") || !strings.Contains(errOut.String(), "sha256 mismatch") {
		t.Fatalf("verify failures: %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), fixtureHash) || !strings.Contains(errOut.String(), manifest.HashBytes(payload)) {
		t.Fatalf("verify failures should show expected and actual hashes: %q", errOut.String())
	}
	if !strings.Contains(out.String(), "ok   local") {
		t.Fatalf("intact entry should still verify: %q", out.String())
	}

	// The single-writer Verify sends successes and failures to the
	// same stream.
	var combined bytes.Buffer
	if err := Verify(&combined, path); err == nil {
		t.Fatal("Verify should fail on tampered manifest")
	}
	if !strings.Contains(combined.String(), "FAIL hello") || !strings.Contains(combined.String(), "ok   local") {
		t.Fatalf("Verify combined output: %q", combined.String())
	}

	// A manifest the loader would reject fails verification too.
	unpinned := filepath.Join(dir, "unpinned.json")
	um := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		{Name: "hello", Source: srv.URL + "/hello.wasm"},
	}}
	if err := um.Save(unpinned); err != nil {
		t.Fatal(err)
	}
	if err := Verify(&bytes.Buffer{}, unpinned); err == nil || !strings.Contains(err.Error(), "requires a pinned sha256") {
		t.Fatalf("verify unpinned: %v", err)
	}
}

func TestVerifySizeMismatch(t *testing.T) {
	payload := fixture
	srv := newServer(t, &payload)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")

	m := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		// Correct hash but wrong pinned size.
		{Name: "hello", Source: srv.URL + "/hello.wasm", SHA256: fixtureHash, Size: 1},
	}}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := VerifyStreams(&out, &errOut, path); err == nil || !strings.Contains(errOut.String(), "size mismatch") {
		t.Fatalf("verify: err %v, failures %q", err, errOut.String())
	}
}

func TestDefaultName(t *testing.T) {
	tests := []struct {
		source, want string
		wantErr      bool
	}{
		{source: "https://example.com/v1.2/hello.wasm", want: "hello"},
		{source: "https://example.com/hello.wasm?sig=abc", want: "hello"},
		{source: "plugins/foo.wasm", want: "foo"},
		{source: "/abs/bar", want: "bar"},
		{source: "https://example.com/", wantErr: true},
	}
	for _, tt := range tests {
		got, err := defaultName(tt.source)
		if tt.wantErr {
			if err == nil {
				t.Errorf("defaultName(%q) = %q, want error", tt.source, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("defaultName(%q) = %q, %v; want %q", tt.source, got, err, tt.want)
		}
	}
}
