package manifest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// ociTestRegistry is an in-process OCI registry stub: content-addressed
// maps behind just the pull endpoints oras-go's remote.Repository needs
// (GET/HEAD /v2/, /v2/<name>/manifests/<tagOrDigest> with a
// Docker-Content-Digest header, /v2/<name>/blobs/<digest>). It listens
// on a loopback address, so the client speaks plain HTTP to it.
type ociTestRegistry struct {
	srv *httptest.Server

	mu        sync.Mutex
	manifests map[string][]byte // "sha256:<hex>" -> OCI image manifest JSON
	tags      map[string]string // "<repo>:<tag>" -> manifest digest
	blobs     map[string][]byte // "sha256:<hex>" -> blob bytes

	blobGets atomic.Int64 // GET blob requests served
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
	if name, ref, ok := cutRoute(req.URL.Path, "/manifests/"); ok {
		dgst := ref
		if !strings.HasPrefix(ref, "sha256:") {
			var found bool
			if dgst, found = r.tags[name+":"+ref]; !found {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		data, found := r.manifests[dgst]
		if !found {
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
	if _, dgst, ok := cutRoute(req.URL.Path, "/blobs/"); ok {
		data, found := r.blobs[dgst]
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if req.Method == http.MethodGet {
			r.blobGets.Add(1)
		}
		// The header echoes the requested digest, like a real registry
		// serving from a content-addressed store; tampered map contents
		// therefore only trip client-side byte verification.
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

// cutRoute splits "/v2/<name><sep><rest>" into name and rest.
func cutRoute(urlPath, sep string) (name, rest string, ok bool) {
	p, found := strings.CutPrefix(urlPath, "/v2/")
	if !found {
		return "", "", false
	}
	i := strings.LastIndex(p, sep)
	if i < 0 {
		return "", "", false
	}
	return p[:i], p[i+len(sep):], true
}

// addWasmArtifact stores wasm as a spec-shaped wasm OCI artifact under
// repo (tagged when tag != ""), optionally mutated by opts before the
// manifest digest is computed. Returns the manifest digest
// ("sha256:<hex>") and the layer digest hex.
func (r *ociTestRegistry) addWasmArtifact(t *testing.T, repo, tag string, wasm []byte, opts ...func(*ocispec.Manifest)) (manifestDigest, layerHex string) {
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
	for _, opt := range opts {
		opt(&m)
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
	for _, l := range m.Layers {
		if _, ok := r.blobs[l.Digest.String()]; !ok {
			r.blobs[l.Digest.String()] = wasm
		}
	}
	return mdgst, strings.TrimPrefix(m.Layers[0].Digest.String(), "sha256:")
}

const testRepo = "test/plugin"

// pinnedOCIPlugin builds a fully pinned manifest entry for an artifact.
func pinnedOCIPlugin(host, manifestDigest, layerHex string, size int64) Plugin {
	return Plugin{
		Name:   "p",
		Source: "oci://" + host + "/" + testRepo + "@" + manifestDigest,
		SHA256: layerHex,
		Size:   size,
	}
}

func TestOCIValidation(t *testing.T) {
	const pinned = "oci://example.com/repo/plugin@sha256:" + goodHash
	sha512Hex := strings.Repeat("ab", 64)
	tests := []struct {
		name    string
		json    string
		wantErr string // substring; "" means expect success
	}{
		{
			name: "pinned oci source without sha256 accepted",
			json: `{"version":1,"plugins":[{"name":"p","source":"` + pinned + `"}]}`,
		},
		{
			name: "pinned oci source with tag and layer pin accepted",
			json: `{"version":1,"plugins":[{"name":"p","source":"` + pinned + `","tag":"v1","sha256":"` + goodHash + `","size":4}]}`,
		},
		{
			name:    "tag-only oci source rejected",
			json:    `{"version":1,"plugins":[{"name":"p","source":"oci://example.com/repo/plugin:v1"}]}`,
			wantErr: "not pinned to a manifest digest (append @sha256:<hex> or run `caddywit manifest pin",
		},
		{
			name:    "bare oci source rejected",
			json:    `{"version":1,"plugins":[{"name":"p","source":"oci://example.com/repo/plugin"}]}`,
			wantErr: "not pinned to a manifest digest",
		},
		{
			name:    "insecure_skip_verify on oci source rejected",
			json:    `{"version":1,"plugins":[{"name":"p","source":"` + pinned + `","insecure_skip_verify":true}]}`,
			wantErr: "insecure_skip_verify is not allowed for OCI source",
		},
		{
			name:    "invalid oci reference rejected",
			json:    `{"version":1,"plugins":[{"name":"p","source":"oci://plugin"}]}`,
			wantErr: "invalid OCI reference",
		},
		{
			name:    "non-sha256 manifest digest rejected",
			json:    `{"version":1,"plugins":[{"name":"p","source":"oci://example.com/repo/plugin@sha512:` + sha512Hex + `"}]}`,
			wantErr: "must use sha256",
		},
		{
			name:    "tag field on filesystem source rejected",
			json:    `{"version":1,"plugins":[{"name":"p","source":"/a.wasm","sha256":"` + goodHash + `","tag":"v1"}]}`,
			wantErr: "tag is only allowed for oci:// sources",
		},
		{
			name:    "tag field on url source rejected",
			json:    `{"version":1,"plugins":[{"name":"p","source":"https://example.com/a.wasm","sha256":"` + goodHash + `","tag":"v1"}]}`,
			wantErr: "tag is only allowed for oci:// sources",
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
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadEditableAllowsTagOnlyOCI(t *testing.T) {
	path := writeManifest(t, `{"version":1,"plugins":[{"name":"p","source":"oci://example.com/repo/plugin:v1"}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("strict Load should reject a tag-only oci source")
	}
	m, err := LoadEditable(path)
	if err != nil {
		t.Fatalf("LoadEditable: %v", err)
	}
	if got := m.Plugins[0].ResolvedSource(); got != "oci://example.com/repo/plugin:v1" {
		t.Fatalf("ResolvedSource = %q, want oci source unchanged", got)
	}
	// Structural oci problems are still rejected in editable mode.
	bad := writeManifest(t, `{"version":1,"plugins":[{"name":"p","source":"oci://plugin"}]}`)
	if _, err := LoadEditable(bad); err == nil || !strings.Contains(err.Error(), "invalid OCI reference") {
		t.Fatalf("LoadEditable invalid ref = %v, want invalid OCI reference", err)
	}
}

func TestOCISourceHelpers(t *testing.T) {
	const dgst = "sha256:" + goodHash
	tagCases := []struct {
		source, want string
	}{
		{"oci://example.com/repo/plugin:v1", "v1"},
		{"oci://example.com:5000/plugin:v1", "v1"},
		{"oci://example.com:5000/plugin", ""},
		{"oci://example.com/repo/plugin@" + dgst, ""},
		{"oci://example.com/repo/plugin:v1@" + dgst, "v1"},
	}
	for _, tt := range tagCases {
		if got := OCITag(tt.source); got != tt.want {
			t.Errorf("OCITag(%q) = %q, want %q", tt.source, got, tt.want)
		}
	}

	pinned, err := PinnedOCISource("oci://example.com:5000/repo/plugin:v1", dgst)
	if err != nil || pinned != "oci://example.com:5000/repo/plugin@"+dgst {
		t.Errorf("PinnedOCISource = %q, %v", pinned, err)
	}
	repo, err := OCIRepositorySource("oci://example.com:5000/repo/plugin:v1@" + dgst)
	if err != nil || repo != "oci://example.com:5000/repo/plugin" {
		t.Errorf("OCIRepositorySource = %q, %v", repo, err)
	}
	if _, err := PinnedOCISource("oci://plugin", dgst); err == nil {
		t.Error("PinnedOCISource should reject an invalid reference")
	}
}

func TestFetchOCIHappyPathAndCache(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, testRepo, "v1", fixture)
	cacheDir := filepath.Join(t.TempDir(), "cache")

	p := pinnedOCIPlugin(reg.host(), mdgst, layerHex, int64(len(fixture)))
	data, err := p.Fetch(context.Background(), cacheDir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(data) != string(fixture) {
		t.Fatalf("Fetch = %q, want fixture", data)
	}
	if reg.blobGets.Load() != 1 {
		t.Fatalf("first fetch: blob GETs = %d, want 1", reg.blobGets.Load())
	}
	if _, err := os.Stat(cachePath(cacheDir, layerHex)); err != nil {
		t.Fatalf("cache file: %v", err)
	}

	// Second fetch is served from the content-addressed cache: the layer
	// digest is known from the OCI manifest before any blob download.
	data, err = p.Fetch(context.Background(), cacheDir)
	if err != nil {
		t.Fatalf("cached Fetch: %v", err)
	}
	if string(data) != string(fixture) || reg.blobGets.Load() != 1 {
		t.Fatalf("cache hit re-downloaded the blob (GETs = %d)", reg.blobGets.Load())
	}

	// An entry without the optional layer pin (no sha256/size) still
	// verifies against the digests in the pinned OCI manifest.
	unpinnedLayer := Plugin{Name: "p", Source: p.Source}
	data, err = unpinnedLayer.Fetch(context.Background(), "")
	if err != nil {
		t.Fatalf("Fetch without layer pin: %v", err)
	}
	if string(data) != string(fixture) {
		t.Fatalf("Fetch without layer pin = %q", data)
	}
}

func TestFetchOCIRejectsUnpinnedSource(t *testing.T) {
	reg := newOCITestRegistry(t)
	reg.addWasmArtifact(t, testRepo, "v1", fixture)

	p := Plugin{Name: "p", Source: "oci://" + reg.host() + "/" + testRepo + ":v1"}
	if _, err := p.Fetch(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "not pinned to a manifest digest") {
		t.Fatalf("Fetch of tag-only source = %v, want pin error", err)
	}
	if reg.blobGets.Load() != 0 {
		t.Fatalf("unpinned source must not download anything (GETs = %d)", reg.blobGets.Load())
	}
}

func TestFetchOCIWrongConfigMediaType(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, testRepo, "", fixture, func(m *ocispec.Manifest) {
		m.Config.MediaType = "application/vnd.oci.image.config.v1+json"
	})

	p := pinnedOCIPlugin(reg.host(), mdgst, layerHex, int64(len(fixture)))
	_, err := p.Fetch(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "config media type") || !strings.Contains(err.Error(), wasmConfigMediaType) {
		t.Fatalf("Fetch = %v, want config media type error", err)
	}
}

func TestFetchOCITwoLayersRejected(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, testRepo, "", fixture, func(m *ocispec.Manifest) {
		extra := []byte("second layer")
		m.Layers = append(m.Layers, ocispec.Descriptor{
			MediaType: wasmLayerMediaType,
			Digest:    digest.FromBytes(extra),
			Size:      int64(len(extra)),
		})
	})

	p := pinnedOCIPlugin(reg.host(), mdgst, layerHex, int64(len(fixture)))
	_, err := p.Fetch(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "exactly one layer, got 2") {
		t.Fatalf("Fetch = %v, want single-layer error", err)
	}
}

func TestFetchOCIWrongLayerMediaType(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, testRepo, "", fixture, func(m *ocispec.Manifest) {
		m.Layers[0].MediaType = "application/vnd.oci.image.layer.v1.tar+gzip"
	})

	p := pinnedOCIPlugin(reg.host(), mdgst, layerHex, int64(len(fixture)))
	if _, err := p.Fetch(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "layer media type") {
		t.Fatalf("Fetch = %v, want layer media type error", err)
	}
}

func TestFetchOCILegacyLayerMediaType(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, testRepo, "", fixture, func(m *ocispec.Manifest) {
		m.Layers[0].MediaType = wasmLayerMediaTypeLegacy
	})

	p := pinnedOCIPlugin(reg.host(), mdgst, layerHex, int64(len(fixture)))
	data, err := p.Fetch(context.Background(), "")
	if err != nil || string(data) != string(fixture) {
		t.Fatalf("Fetch with legacy layer media type = %q, %v", data, err)
	}
}

func TestFetchOCITamperedBlobNotCached(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, testRepo, "", fixture)
	// Serve tampered bytes under the layer's content address.
	reg.mu.Lock()
	reg.blobs["sha256:"+layerHex] = []byte("\x00asm-tampered-bytes-xx")
	reg.mu.Unlock()
	cacheDir := filepath.Join(t.TempDir(), "cache")

	p := pinnedOCIPlugin(reg.host(), mdgst, layerHex, int64(len(fixture)))
	_, err := p.Fetch(context.Background(), cacheDir)
	if err == nil || !strings.Contains(err.Error(), "wasm layer sha256 mismatch") {
		t.Fatalf("Fetch = %v, want layer hash mismatch", err)
	}
	// Unverified bytes must never be cached.
	if _, statErr := os.Stat(cachePath(cacheDir, layerHex)); !os.IsNotExist(statErr) {
		t.Fatalf("tampered blob must not be cached: %v", statErr)
	}
}

func TestFetchOCILayerPinMismatch(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, _ := reg.addWasmArtifact(t, testRepo, "", fixture)

	// Entry pins a layer hash that disagrees with the OCI manifest: the
	// mismatch is detected from the manifest alone, before any blob
	// download.
	p := pinnedOCIPlugin(reg.host(), mdgst, goodHash, int64(len(fixture)))
	_, err := p.Fetch(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "wasm layer sha256 mismatch") || !strings.Contains(err.Error(), goodHash) {
		t.Fatalf("Fetch = %v, want layer pin mismatch", err)
	}
	if reg.blobGets.Load() != 0 {
		t.Fatalf("layer pin mismatch must be caught before the blob download (GETs = %d)", reg.blobGets.Load())
	}
}

func TestFetchOCISizeMismatch(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, testRepo, "", fixture)

	p := pinnedOCIPlugin(reg.host(), mdgst, layerHex, 4)
	_, err := p.Fetch(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "size mismatch: manifest pins 4 bytes") {
		t.Fatalf("Fetch = %v, want size mismatch", err)
	}
	if reg.blobGets.Load() != 0 {
		t.Fatalf("size mismatch must be caught before the blob download (GETs = %d)", reg.blobGets.Load())
	}
}

func TestFetchOCITamperedManifest(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, testRepo, "", fixture)
	// Serve a different (well-formed) OCI manifest under the pinned
	// digest. The stub still echoes the requested digest in
	// Docker-Content-Digest, so only client-side content verification
	// can catch the swap.
	otherDgst, _ := reg.addWasmArtifact(t, testRepo, "", []byte("other wasm bytes"))
	reg.mu.Lock()
	reg.manifests[mdgst] = reg.manifests[otherDgst]
	reg.mu.Unlock()

	p := pinnedOCIPlugin(reg.host(), mdgst, layerHex, int64(len(fixture)))
	_, err := p.Fetch(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Fetch of tampered manifest = %v, want digest mismatch", err)
	}
	if reg.blobGets.Load() != 0 {
		t.Fatalf("tampered manifest must be caught before any blob download (GETs = %d)", reg.blobGets.Load())
	}
}

func TestResolveOCI(t *testing.T) {
	reg := newOCITestRegistry(t)
	mdgst, layerHex := reg.addWasmArtifact(t, testRepo, "v1", fixture)

	art, err := ResolveOCI(context.Background(), "oci://"+reg.host()+"/"+testRepo+":v1")
	if err != nil {
		t.Fatalf("ResolveOCI: %v", err)
	}
	if art.ManifestDigest != mdgst || art.LayerSHA256 != layerHex || art.LayerSize != int64(len(fixture)) {
		t.Fatalf("ResolveOCI = %+v, want digest %s layer %s size %d", art, mdgst, layerHex, len(fixture))
	}

	// Resolving by digest works too.
	art, err = ResolveOCI(context.Background(), "oci://"+reg.host()+"/"+testRepo+"@"+mdgst)
	if err != nil || art.ManifestDigest != mdgst {
		t.Fatalf("ResolveOCI by digest = %+v, %v", art, err)
	}

	if _, err := ResolveOCI(context.Background(), "oci://"+reg.host()+"/"+testRepo+":nope"); err == nil {
		t.Fatal("ResolveOCI of unknown tag should fail")
	}
}
