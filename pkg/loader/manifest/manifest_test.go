package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeManifest writes contents to a caddy-wit.json in a fresh temp dir
// and returns its path.
func writeManifest(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const goodHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" // sha256("test")

func TestLoadValidation(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string // substring; "" means expect success
	}{
		{
			name: "valid url entry",
			json: `{"version":1,"plugins":[{"name":"hello","source":"https://example.com/hello.wasm","sha256":"` + goodHash + `"}]}`,
		},
		{
			name: "valid file entry with size and modules",
			json: `{"version":1,"plugins":[{"name":"hello","source":"/abs/hello.wasm","sha256":"` + goodHash + `","size":4,"modules":["http.handlers.hello"]}]}`,
		},
		{
			name: "valid insecure file entry without sha256",
			json: `{"version":1,"plugins":[{"name":"dev","source":"./dev.wasm","insecure_skip_verify":true}]}`,
		},
		{
			name:    "empty manifest ok",
			json:    `{"version":1,"plugins":[]}`,
			wantErr: "",
		},
		{
			name:    "wrong version",
			json:    `{"version":2,"plugins":[]}`,
			wantErr: "unsupported manifest version 2",
		},
		{
			name: "duplicate names",
			json: `{"version":1,"plugins":[
				{"name":"hello","source":"/a.wasm","sha256":"` + goodHash + `"},
				{"name":"hello","source":"/b.wasm","sha256":"` + goodHash + `"}]}`,
			wantErr: `plugin "hello": duplicate name`,
		},
		{
			name:    "missing name",
			json:    `{"version":1,"plugins":[{"source":"/a.wasm","sha256":"` + goodHash + `"}]}`,
			wantErr: "name is required",
		},
		{
			name:    "missing source",
			json:    `{"version":1,"plugins":[{"name":"hello","sha256":"` + goodHash + `"}]}`,
			wantErr: "source is required",
		},
		{
			name:    "url without sha256 rejected",
			json:    `{"version":1,"plugins":[{"name":"hello","source":"https://example.com/hello.wasm"}]}`,
			wantErr: "requires a pinned sha256",
		},
		{
			name:    "url with insecure_skip_verify still rejected",
			json:    `{"version":1,"plugins":[{"name":"hello","source":"https://example.com/hello.wasm","insecure_skip_verify":true}]}`,
			wantErr: "insecure_skip_verify is only allowed for filesystem sources",
		},
		{
			name:    "file without sha256 and without insecure rejected",
			json:    `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm"}]}`,
			wantErr: "sha256 is required unless insecure_skip_verify",
		},
		{
			name:    "sha256 wrong length",
			json:    `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm","sha256":"abcd"}]}`,
			wantErr: "sha256 must be 64 hex characters",
		},
		{
			name:    "sha256 not hex",
			json:    `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm","sha256":"` + strings.Repeat("zz", 32) + `"}]}`,
			wantErr: "not valid hex",
		},
		{
			name:    "negative size",
			json:    `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm","sha256":"` + goodHash + `","size":-5}]}`,
			wantErr: "size must not be negative",
		},
		{
			name: "valid permissions",
			json: `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm","sha256":"` + goodHash + `","permissions":["http","tcp"]}]}`,
		},
		{
			name: "empty permissions ok",
			json: `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm","sha256":"` + goodHash + `","permissions":[]}]}`,
		},
		{
			name:    "unknown permission rejected with valid values listed",
			json:    `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm","sha256":"` + goodHash + `","permissions":["udp"]}]}`,
			wantErr: `unknown permission "udp" (valid permissions: "http", "tcp")`,
		},
		{
			name:    "permission case-sensitive",
			json:    `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm","sha256":"` + goodHash + `","permissions":["HTTP"]}]}`,
			wantErr: `unknown permission "HTTP"`,
		},
		{
			name:    "duplicate permission rejected",
			json:    `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm","sha256":"` + goodHash + `","permissions":["http","http"]}]}`,
			wantErr: `duplicate permission "http"`,
		},
		{
			name:    "unknown field rejected",
			json:    `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm","sha265":"` + goodHash + `"}]}`,
			wantErr: "unknown field",
		},
		{
			name:    "misspelled permissions field rejected, not silently ignored",
			json:    `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm","sha256":"` + goodHash + `","permisions":["http"]}]}`,
			wantErr: "unknown field",
		},
		{
			name:    "not json",
			json:    `hello`,
			wantErr: "parsing manifest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeManifest(t, tt.json)
			_, err := Load(path)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Load: unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Load: expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load: error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	path := writeManifest(t, `{"version":1,"plugins":[
		{"name":"rel","source":"plugins/hello.wasm","sha256":"`+goodHash+`"},
		{"name":"abs","source":"/abs/hello.wasm","sha256":"`+goodHash+`"},
		{"name":"url","source":"https://example.com/hello.wasm","sha256":"`+goodHash+`"}]}`)
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)

	if got, want := m.Plugins[0].ResolvedSource(), filepath.Join(dir, "plugins", "hello.wasm"); got != want {
		t.Errorf("relative: ResolvedSource = %q, want %q", got, want)
	}
	if got, want := m.Plugins[0].Source, "plugins/hello.wasm"; got != want {
		t.Errorf("relative: Source rewritten to %q, want original %q", got, want)
	}
	if got := m.Plugins[1].ResolvedSource(); got != "/abs/hello.wasm" {
		t.Errorf("absolute: ResolvedSource = %q, want unchanged", got)
	}
	if got := m.Plugins[2].ResolvedSource(); got != "https://example.com/hello.wasm" {
		t.Errorf("url: ResolvedSource = %q, want unchanged", got)
	}
}

func TestLoadNormalizesHashCase(t *testing.T) {
	path := writeManifest(t, `{"version":1,"plugins":[{"name":"hello","source":"/a.wasm","sha256":"`+strings.ToUpper(goodHash)+`"}]}`)
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Plugins[0].SHA256 != goodHash {
		t.Fatalf("SHA256 = %q, want lowercased %q", m.Plugins[0].SHA256, goodHash)
	}
}

func TestLoadEditableAllowsUnpinned(t *testing.T) {
	path := writeManifest(t, `{"version":1,"plugins":[{"name":"hello","source":"https://example.com/hello.wasm"}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("strict Load should reject an unpinned URL entry")
	}
	m, err := LoadEditable(path)
	if err != nil {
		t.Fatalf("LoadEditable: %v", err)
	}
	if len(m.Plugins) != 1 || m.Plugins[0].SHA256 != "" {
		t.Fatalf("unexpected manifest: %+v", m)
	}
	// Structural problems are still rejected.
	dup := writeManifest(t, `{"version":1,"plugins":[
		{"name":"x","source":"/a.wasm"},{"name":"x","source":"/b.wasm"}]}`)
	if _, err := LoadEditable(dup); err == nil {
		t.Fatal("LoadEditable should still reject duplicate names")
	}
}

func TestSaveFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")

	empty := &Manifest{Version: Version}
	if err := empty.Save(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"version\": 1,\n  \"plugins\": []\n}\n"
	if string(data) != want {
		t.Fatalf("empty manifest = %q, want %q", data, want)
	}

	m := &Manifest{Version: Version, Plugins: []Plugin{{
		Name:   "hello",
		Source: "https://example.com/hello.wasm",
		SHA256: goodHash,
		Size:   4,
	}}}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("round trip Load: %v", err)
	}
	rp, wp := got.Plugins[0], m.Plugins[0]
	if rp.Name != wp.Name || rp.Source != wp.Source || rp.SHA256 != wp.SHA256 || rp.Size != wp.Size {
		t.Fatalf("round trip = %+v, want %+v", rp, wp)
	}
	data, _ = os.ReadFile(path)
	if !strings.HasSuffix(string(data), "}\n") {
		t.Fatalf("manifest should end with a trailing newline, got %q", data)
	}
	// Stable field order: name before source before sha256 before size.
	s := string(data)
	if !(strings.Index(s, `"name"`) < strings.Index(s, `"source"`) &&
		strings.Index(s, `"source"`) < strings.Index(s, `"sha256"`) &&
		strings.Index(s, `"sha256"`) < strings.Index(s, `"size"`)) {
		t.Fatalf("unexpected field order:\n%s", s)
	}
}
