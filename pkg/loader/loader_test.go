package loader

// These tests exercise the runtime-independent parts of package loader:
// manifest loading via the exported aliases and the module allowlist
// check. The full fetch/verify/cache test suite lives in
// loader/manifest. Nothing here executes wasm.

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/elee1766/caddy-wit/pkg/runtime"
	"github.com/elee1766/caddy-wit/pkg/shim"
)

func TestLoadManifestAlias(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")
	contents := `{
  "version": 1,
  "plugins": [
    {
      "name": "hello",
      "source": "plugins/hello.wasm",
      "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "modules": ["http.handlers.hello"]
    }
  ]
}
`
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(m.Plugins) != 1 || m.Plugins[0].Name != "hello" {
		t.Fatalf("manifest = %+v", m)
	}
	var p ManifestPlugin = m.Plugins[0]
	if got, want := p.ResolvedSource(), filepath.Join(dir, "plugins", "hello.wasm"); got != want {
		t.Fatalf("ResolvedSource = %q, want %q", got, want)
	}

	// URL entries without a pinned sha256 are rejected.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"version":1,"plugins":[{"name":"x","source":"https://example.com/x.wasm"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(bad); err == nil || !strings.Contains(err.Error(), "requires a pinned sha256") {
		t.Fatalf("LoadManifest(bad) = %v, want pinned sha256 error", err)
	}
}

func TestPermissionsFromManifest(t *testing.T) {
	tests := []struct {
		name  string
		perms []string
		want  runtime.Permissions
	}{
		{name: "nil grants nothing", perms: nil, want: runtime.Permissions{}},
		{name: "empty grants nothing", perms: []string{}, want: runtime.Permissions{}},
		{name: "http only", perms: []string{"http"}, want: runtime.Permissions{HTTP: true}},
		{name: "tcp only", perms: []string{"tcp"}, want: runtime.Permissions{TCP: true}},
		{name: "both", perms: []string{"http", "tcp"}, want: runtime.Permissions{HTTP: true, TCP: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := permissionsFromManifest(tt.perms); got != tt.want {
				t.Fatalf("permissionsFromManifest(%v) = %+v, want %+v", tt.perms, got, tt.want)
			}
		})
	}
}

// TestLoadedPluginCarriesPermissions checks the loader-side plumbing: a
// manifest entry's permissions list, converted once, rides on the
// shim.LoadedPlugin every shim instance is constructed from (loadPlugin
// does exactly this assignment; the wasm-compiling path itself needs a
// live runtime and is covered by integration tests).
func TestLoadedPluginCarriesPermissions(t *testing.T) {
	path := writeTestManifest(t, `{"version":1,"plugins":[{
		"name":"dns","source":"/abs/dns.wasm",
		"sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"permissions":["http"]}]}`)
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	lp := &shim.LoadedPlugin{
		Name:        m.Plugins[0].Name,
		Permissions: permissionsFromManifest(m.Plugins[0].Permissions),
	}
	if want := (runtime.Permissions{HTTP: true}); lp.Permissions != want {
		t.Fatalf("LoadedPlugin.Permissions = %+v, want %+v", lp.Permissions, want)
	}
}

func writeTestManifest(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "caddy-wit.json")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDisallowedModules(t *testing.T) {
	tests := []struct {
		name     string
		allow    []string
		declared []string
		want     []string
	}{
		{
			name:     "all allowed",
			allow:    []string{"http.handlers.hello", "http.matchers.hello"},
			declared: []string{"http.handlers.hello"},
			want:     nil,
		},
		{
			name:     "extra declared",
			allow:    []string{"http.handlers.hello"},
			declared: []string{"http.handlers.hello", "caddy.storage.evil", "events.handlers.evil"},
			want:     []string{"caddy.storage.evil", "events.handlers.evil"},
		},
		{
			name:     "empty allowlist rejects everything",
			allow:    []string{},
			declared: []string{"http.handlers.hello"},
			want:     []string{"http.handlers.hello"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := disallowedModules(tt.allow, tt.declared); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("disallowedModules = %v, want %v", got, tt.want)
			}
		})
	}
}
