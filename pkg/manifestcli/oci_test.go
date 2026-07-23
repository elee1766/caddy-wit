package manifestcli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/elee1766/caddy-wit/pkg/loader/manifest"
)

// ociTestRegistry is an in-process OCI registry stub: content-addressed
// maps behind just the pull endpoints oras-go needs. It listens on a
// loopback address, so the client speaks plain HTTP to it. (A sibling of
// the stub in loader/manifest's tests; test helpers cannot be shared
// across packages.)
type ociTestRegistry struct {
	srv *httptest.Server

	mu        sync.Mutex
	manifests map[string][]byte // "sha256:<hex>" -> OCI image manifest JSON
	tags      map[string]string // "<repo>:<tag>" -> manifest digest
	blobs     map[string][]byte // "sha256:<hex>" -> blob bytes
}

func newOCITestRegistry(t *testing.T) *ociTestRegistry {
	t.Helper()
	r := &ociTestRegistry{
		manifests: map[string][]byte{},
		tags:      map[string]string{},
		blobs:     map[string][]byte{},
	}
	r.srv = httptest.NewServer(r)
	t.Cleanup(r.srv.Close)
	return r
}

// host returns the registry's host:port.
func (r *ociTestRegistry) host() string {
	return strings.TrimPrefix(r.srv.URL, "http://")
}

func (r *ociTestRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if req.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, found := strings.CutPrefix(req.URL.Path, "/v2/")
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if i := strings.LastIndex(p, "/manifests/"); i >= 0 {
		name, ref := p[:i], p[i+len("/manifests/"):]
		dgst := ref
		if !strings.HasPrefix(ref, "sha256:") {
			if dgst, found = r.tags[name+":"+ref]; !found {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		data, ok := r.manifests[dgst]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
		w.Header().Set("Docker-Content-Digest", dgst)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		if req.Method == http.MethodGet {
			w.Write(data)
		}
		return
	}
	if i := strings.LastIndex(p, "/blobs/"); i >= 0 {
		dgst := p[i+len("/blobs/"):]
		data, ok := r.blobs[dgst]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Docker-Content-Digest", dgst)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		if req.Method == http.MethodGet {
			w.Write(data)
		}
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

// addWasmArtifact stores wasm as a spec-shaped wasm OCI artifact under
// repo (tagged when tag != "") and returns the manifest digest
// ("sha256:<hex>") and the layer digest hex.
func (r *ociTestRegistry) addWasmArtifact(t *testing.T, repo, tag string, wasm []byte) (manifestDigest, layerHex string) {
	t.Helper()
	config := []byte("{}")
	m := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: "application/vnd.wasm.config.v0+json",
			Digest:    digest.FromBytes(config),
			Size:      int64(len(config)),
		},
		Layers: []ocispec.Descriptor{{
			MediaType: "application/wasm",
			Digest:    digest.FromBytes(wasm),
			Size:      int64(len(wasm)),
		}},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	mdgst := digest.FromBytes(raw).String()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[mdgst] = raw
	if tag != "" {
		r.tags[repo+":"+tag] = mdgst
	}
	r.blobs[m.Config.Digest.String()] = config
	r.blobs[m.Layers[0].Digest.String()] = wasm
	return mdgst, strings.TrimPrefix(m.Layers[0].Digest.String(), "sha256:")
}

func TestAddOCI(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, "test/plugin", "v1", fixture)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")
	mustInit(t, path)

	// Add by tag: the source is stored pinned to the manifest digest,
	// with the tag moved to the informational tag field and the wasm
	// layer digest/size in sha256/size.
	source := "oci://" + reg.host() + "/test/plugin:v1"
	pinned := "oci://" + reg.host() + "/test/plugin@" + mdgst
	var out bytes.Buffer
	if err := Add(&out, path, source, "", ""); err != nil {
		t.Fatalf("add oci: %v", err)
	}
	if !strings.Contains(out.String(), `added "plugin"`) || !strings.Contains(out.String(), pinned) {
		t.Fatalf("add oci output: %q", out.String())
	}
	m := mustLoadEditable(t, path)
	if len(m.Plugins) != 1 {
		t.Fatalf("plugins = %+v", m.Plugins)
	}
	p := m.Plugins[0]
	if p.Name != "plugin" || p.Source != pinned || p.Tag != "v1" || p.SHA256 != layerHex || p.Size != int64(len(fixture)) {
		t.Fatalf("entry = %+v", p)
	}

	// The pinned manifest passes strict loading (the loader's gate).
	if _, err := manifest.Load(path); err != nil {
		t.Fatalf("strict Load of pinned oci manifest: %v", err)
	}

	// Adding the same tag again resolves to the same pinned source and
	// is rejected as a duplicate.
	if err := Add(&out, path, source, "plugin2", ""); err == nil || !strings.Contains(err.Error(), "entry for source") {
		t.Fatalf("dup oci source: %v", err)
	}

	// An unresolvable reference is rejected and nothing is appended.
	if err := Add(&out, path, "oci://"+reg.host()+"/test/plugin:nope", "other", ""); err == nil {
		t.Fatal("add of unknown tag should fail")
	}
	if m := mustLoadEditable(t, path); len(m.Plugins) != 1 {
		t.Fatalf("failed add must not append: %+v", m.Plugins)
	}
}

func TestAddOCIByDigest(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, "test/plugin", "", fixture)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")
	mustInit(t, path)

	source := "oci://" + reg.host() + "/test/plugin@" + mdgst
	if err := Add(&bytes.Buffer{}, path, source, "", ""); err != nil {
		t.Fatalf("add oci by digest: %v", err)
	}
	p := mustLoadEditable(t, path).Plugins[0]
	if p.Source != source || p.Tag != "" || p.SHA256 != layerHex || p.Size != int64(len(fixture)) {
		t.Fatalf("entry = %+v", p)
	}
}

func TestPinOCI(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst1, layerHex1 := reg.addWasmArtifact(t, "test/plugin", "v1", fixture)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")

	// Hand-written manifest: a tag-only entry (tag in the source) and a
	// digest-only entry.
	m := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		{Name: "tagged", Source: "oci://" + reg.host() + "/test/plugin:v1"},
		{Name: "digested", Source: "oci://" + reg.host() + "/test/plugin@" + mdgst1},
	}}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Pin(&out, path); err != nil {
		t.Fatalf("pin: %v", err)
	}
	if !strings.Contains(out.String(), layerHex1) {
		t.Fatalf("pin output: %q", out.String())
	}
	got := mustLoadEditable(t, path)
	pinned := "oci://" + reg.host() + "/test/plugin@" + mdgst1
	if p := got.Plugins[0]; p.Source != pinned || p.Tag != "v1" || p.SHA256 != layerHex1 || p.Size != int64(len(fixture)) {
		t.Fatalf("tagged entry = %+v", p)
	}
	if p := got.Plugins[1]; p.Source != pinned || p.Tag != "" || p.SHA256 != layerHex1 || p.Size != int64(len(fixture)) {
		t.Fatalf("digested entry = %+v", p)
	}

	// The tag moves to a new artifact: re-pinning follows it for the
	// tagged entry, rewriting source, sha256, and size; the digest-only
	// entry stays on its digest.
	newWasm := []byte("\x00asm-v2-plugin-bytes-longer")
	mdgst2, layerHex2 := reg.addWasmArtifact(t, "test/plugin", "v1", newWasm)
	if err := Pin(&out, path); err != nil {
		t.Fatal(err)
	}
	got = mustLoadEditable(t, path)
	if p := got.Plugins[0]; p.Source != "oci://"+reg.host()+"/test/plugin@"+mdgst2 || p.Tag != "v1" || p.SHA256 != layerHex2 || p.Size != int64(len(newWasm)) {
		t.Fatalf("re-pinned tagged entry = %+v", p)
	}
	if p := got.Plugins[1]; p.Source != pinned || p.SHA256 != layerHex1 {
		t.Fatalf("digest-only entry must not follow the tag: %+v", p)
	}
}

func TestPinOCIUnreachable(t *testing.T) {
	reg := newOCITestRegistry(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")
	m := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		{Name: "gone", Source: "oci://" + reg.host() + "/test/plugin:v1"},
	}}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	err := Pin(&bytes.Buffer{}, path)
	if err == nil || !strings.Contains(err.Error(), "manifest not updated") {
		t.Fatalf("pin of unreachable oci entry: %v", err)
	}
}

func TestVerifyOCI(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, "test/plugin", "v1", fixture)
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")

	m := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		{
			Name:   "plugin",
			Source: "oci://" + reg.host() + "/test/plugin@" + mdgst,
			Tag:    "v1",
			SHA256: layerHex,
			Size:   int64(len(fixture)),
		},
	}}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if err := VerifyStreams(&out, &errOut, path); err != nil {
		t.Fatalf("verify: %v (errOut %q)", err, errOut.String())
	}
	if !strings.Contains(out.String(), "ok   plugin") || !strings.Contains(out.String(), layerHex) {
		t.Fatalf("verify output: %q", out.String())
	}

	// The registry serves tampered layer bytes: verify fails.
	reg.mu.Lock()
	reg.blobs["sha256:"+layerHex] = []byte("tampered")
	reg.mu.Unlock()
	out.Reset()
	errOut.Reset()
	err := VerifyStreams(&out, &errOut, path)
	if err == nil || !strings.Contains(errOut.String(), "FAIL plugin") || !strings.Contains(errOut.String(), "mismatch") {
		t.Fatalf("verify after tamper: err %v, failures %q", err, errOut.String())
	}

	// A manifest the loader would reject (tag-only oci source) fails
	// verification too.
	unpinned := filepath.Join(dir, "unpinned.json")
	um := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{
		{Name: "plugin", Source: "oci://" + reg.host() + "/test/plugin:v1"},
	}}
	if err := um.Save(unpinned); err != nil {
		t.Fatal(err)
	}
	if err := Verify(&bytes.Buffer{}, unpinned); err == nil || !strings.Contains(err.Error(), "not pinned to a manifest digest") {
		t.Fatalf("verify unpinned oci: %v", err)
	}
}

func TestDefaultNameOCI(t *testing.T) {
	const dgst = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	tests := []struct {
		source, want string
		wantErr      bool
	}{
		{source: "oci://ghcr.io/acme/plugins/hello:v1", want: "hello"},
		{source: "oci://ghcr.io/acme/hello.wasm@" + dgst, want: "hello"},
		{source: "oci://127.0.0.1:5000/hello:v1@" + dgst, want: "hello"},
		{source: "oci://ghcr.io", wantErr: true},
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
