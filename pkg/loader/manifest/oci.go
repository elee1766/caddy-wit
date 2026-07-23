package manifest

// OCI plugin sources: CNCF Wasm OCI Artifacts pulled from OCI registries.
//
// A source of the form "oci://<registry>/<repo>[:tag][@sha256:<hex>]"
// names an artifact per the CNCF Wasm OCI Artifact spec
// (https://tag-runtime.cncf.io/wgs/wasm/deliverables/wasm-oci-artifact/):
// an OCI image manifest whose config media type is
// "application/vnd.wasm.config.v0+json" and whose single layer holds the
// raw wasm bytes.
//
// The integrity model mirrors URL sources but pins the OCI manifest
// digest instead of the wasm hash directly: strict loading requires the
// source to carry "@sha256:<hex>", which fixes the manifest bytes, which
// in turn fix the layer digest, which the downloaded wasm is verified
// against. The optional sha256 field additionally pins the layer bytes.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

const (
	// ociScheme prefixes manifest sources that name a wasm OCI artifact.
	ociScheme = "oci://"

	// ociDigestPrefix is the only digest algorithm accepted in pinned
	// oci:// sources and OCI manifest layer descriptors.
	ociDigestPrefix = "sha256:"

	// wasmConfigMediaType is the config media type REQUIRED by the CNCF
	// Wasm OCI Artifact spec v0; manifests with any other config media
	// type are rejected.
	wasmConfigMediaType = "application/vnd.wasm.config.v0+json"

	// wasmLayerMediaType is the spec v0 media type of the single layer
	// carrying the raw wasm bytes.
	wasmLayerMediaType = "application/wasm"

	// wasmLayerMediaTypeLegacy is accepted as an alias for
	// wasmLayerMediaType: earlier wasm-to-OCI tooling published layers
	// under this media type before the CNCF spec settled on
	// "application/wasm".
	wasmLayerMediaTypeLegacy = "application/vnd.wasm.content.layer.v1+wasm"

	// maxOCIManifestSize caps the OCI image manifest JSON document
	// itself (not the wasm layer, which is capped separately).
	maxOCIManifestSize = 4 << 20 // 4 MiB
)

// IsOCI reports whether source is an oci:// reference to a wasm OCI
// artifact rather than a URL or filesystem path.
func IsOCI(source string) bool {
	return strings.HasPrefix(source, ociScheme)
}

// ociPlainHTTP decides whether to speak plain HTTP (instead of HTTPS) to
// a registry host. The default mirrors Docker's insecure-by-default
// treatment of loopback registries: local dev registries rarely have
// TLS, and the digest pin still guarantees integrity of what we pull.
// It is a package-level variable so tests can override it; it is
// deliberately not a manifest field.
var ociPlainHTTP = func(registryHost string) bool {
	host := registryHost
	if h, _, err := net.SplitHostPort(registryHost); err == nil {
		host = h
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// parseOCISource strips the oci:// scheme and parses the remainder as an
// OCI artifact reference.
func parseOCISource(source string) (registry.Reference, error) {
	if !IsOCI(source) {
		return registry.Reference{}, fmt.Errorf("not an oci:// source: %q", source)
	}
	ref, err := registry.ParseReference(strings.TrimPrefix(source, ociScheme))
	if err != nil {
		return registry.Reference{}, fmt.Errorf("invalid OCI reference %q: %w", source, err)
	}
	return ref, nil
}

// ociSourceDigestHex returns the hex part of the manifest digest an
// oci:// reference is pinned to, or "" when the reference is tag-only or
// bare. Non-sha256 digests report an error: the source form only admits
// sha256 pins.
func ociSourceDigestHex(ref registry.Reference) (string, error) {
	if !strings.Contains(ref.Reference, ":") {
		return "", nil // empty or a tag
	}
	hexPart, ok := strings.CutPrefix(ref.Reference, ociDigestPrefix)
	if !ok {
		return "", fmt.Errorf("OCI manifest digest %q must use sha256", ref.Reference)
	}
	if err := checkSHA256Hex(hexPart); err != nil {
		return "", fmt.Errorf("OCI manifest digest %q: %w", ref.Reference, err)
	}
	return hexPart, nil
}

// OCITag returns the tag component of an oci:// source, or "" when the
// source is digest-only or bare. Unlike registry.ParseReference (which
// drops a tag that appears alongside a digest), this preserves the tag
// so pin tooling can record it.
func OCITag(source string) string {
	path := strings.TrimPrefix(source, ociScheme)
	if _, rest, ok := strings.Cut(path, "/"); ok {
		path = rest // drop <registry>/ so a registry port is not mistaken for a tag
	} else {
		return ""
	}
	if i := strings.Index(path, "@"); i != -1 {
		path = path[:i]
	}
	if i := strings.Index(path, ":"); i != -1 {
		return path[i+1:]
	}
	return ""
}

// PinnedOCISource rewrites an oci:// source to its digest-pinned form:
// any tag or digest is dropped and manifestDigest ("sha256:<hex>") is
// appended.
func PinnedOCISource(source, manifestDigest string) (string, error) {
	ref, err := parseOCISource(source)
	if err != nil {
		return "", err
	}
	return ociScheme + ref.Registry + "/" + ref.Repository + "@" + manifestDigest, nil
}

// OCIRepositorySource returns the oci:// source stripped of any tag or
// digest: "oci://<registry>/<repository>".
func OCIRepositorySource(source string) (string, error) {
	ref, err := parseOCISource(source)
	if err != nil {
		return "", err
	}
	return ociScheme + ref.Registry + "/" + ref.Repository, nil
}

// validateOCI checks the rules specific to oci:// sources. ref is the
// diagnostic label for the entry ("plugin %q" or "plugins[%d]").
func (p *Plugin) validateOCI(strict bool, ref string) error {
	if p.InsecureSkipVerify {
		// Same rationale as URLs: remote content is mutable and
		// unauthenticated; the digest pin is the integrity mechanism and
		// must never be skipped.
		return fmt.Errorf("%s: insecure_skip_verify is not allowed for OCI source %q (the manifest digest is the integrity mechanism)", ref, p.Source)
	}
	parsed, err := parseOCISource(p.Source)
	if err != nil {
		return fmt.Errorf("%s: %w", ref, err)
	}
	hexPart, err := ociSourceDigestHex(parsed)
	if err != nil {
		return fmt.Errorf("%s: %w", ref, err)
	}
	if strict && hexPart == "" {
		return fmt.Errorf("%s: OCI source %q is not pinned to a manifest digest (append @sha256:<hex> or run `caddywit manifest pin <path>`)", ref, p.Source)
	}
	return nil
}

// OCIArtifact is the result of resolving a wasm OCI artifact: the digest
// of its OCI image manifest (the pin that belongs in the source) and the
// digest/size of its single wasm layer (what belongs in the sha256/size
// fields).
type OCIArtifact struct {
	ManifestDigest string // "sha256:<hex>" of the OCI image manifest bytes
	LayerSHA256    string // hex-encoded sha256 of the wasm layer bytes
	LayerSize      int64  // size in bytes of the wasm layer

	// layer is the full layer descriptor, kept for fetching the blob.
	layer ocispec.Descriptor
}

// ociRepository builds a client for one repository. Authentication uses
// the local docker credential chain (config.json, credential helpers)
// when one can be loaded, and falls back to anonymous access otherwise.
func ociRepository(ref registry.Reference) (*remote.Repository, error) {
	repo, err := remote.NewRepository(ref.Registry + "/" + ref.Repository)
	if err != nil {
		return nil, fmt.Errorf("building OCI repository client for %s/%s: %w", ref.Registry, ref.Repository, err)
	}
	client := &auth.Client{Cache: auth.NewCache()}
	if store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{}); err == nil {
		client.Credential = credentials.Credential(store)
	}
	repo.Client = client
	repo.PlainHTTP = ociPlainHTTP(ref.Registry)
	return repo, nil
}

// fetchOCIManifest fetches the OCI image manifest for reference (a tag
// or a digest) from repo, verifies the manifest bytes against the
// resolved digest, and enforces the wasm artifact shape: config media
// type, exactly one layer, wasm layer media type, sha256 layer digest.
func fetchOCIManifest(ctx context.Context, repo *remote.Repository, reference string) (*OCIArtifact, error) {
	desc, rc, err := repo.Manifests().FetchReference(ctx, reference)
	if err != nil {
		return nil, fmt.Errorf("fetching OCI manifest %s: %w", reference, err)
	}
	defer rc.Close()
	if desc.MediaType != ocispec.MediaTypeImageManifest {
		return nil, fmt.Errorf("OCI manifest %s: media type %q is not an OCI image manifest (%s)", reference, desc.MediaType, ocispec.MediaTypeImageManifest)
	}
	if desc.Size > maxOCIManifestSize {
		return nil, fmt.Errorf("OCI manifest %s: %d bytes exceeds %d byte limit", reference, desc.Size, int64(maxOCIManifestSize))
	}
	raw, err := io.ReadAll(io.LimitReader(rc, maxOCIManifestSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading OCI manifest %s: %w", reference, err)
	}
	if int64(len(raw)) > maxOCIManifestSize {
		return nil, fmt.Errorf("OCI manifest %s: exceeds %d byte limit", reference, int64(maxOCIManifestSize))
	}

	// Explicitly verify the manifest bytes against the digest they were
	// resolved to; nothing downstream may trust unverified bytes. (The
	// registry client checks response headers, not the body itself.)
	manifestDigest := ociDigestPrefix + HashBytes(raw)
	if manifestDigest != desc.Digest.String() {
		return nil, fmt.Errorf("OCI manifest %s: content digest %s does not match resolved digest %s", reference, manifestDigest, desc.Digest)
	}

	var im ocispec.Manifest
	if err := json.Unmarshal(raw, &im); err != nil {
		return nil, fmt.Errorf("parsing OCI manifest %s: %w", reference, err)
	}
	if im.Config.MediaType != wasmConfigMediaType {
		return nil, fmt.Errorf("OCI manifest %s: config media type %q is not a wasm artifact config (%s)", reference, im.Config.MediaType, wasmConfigMediaType)
	}
	// Spec v0 consumers MUST reject manifests with more than one layer.
	if len(im.Layers) != 1 {
		return nil, fmt.Errorf("OCI manifest %s: wasm artifacts must have exactly one layer, got %d", reference, len(im.Layers))
	}
	layer := im.Layers[0]
	if layer.MediaType != wasmLayerMediaType && layer.MediaType != wasmLayerMediaTypeLegacy {
		return nil, fmt.Errorf("OCI manifest %s: layer media type %q is not wasm content (%s or %s)", reference, layer.MediaType, wasmLayerMediaType, wasmLayerMediaTypeLegacy)
	}
	layerHex, ok := strings.CutPrefix(layer.Digest.String(), ociDigestPrefix)
	if !ok {
		return nil, fmt.Errorf("OCI manifest %s: layer digest %q must use sha256", reference, layer.Digest)
	}
	if err := checkSHA256Hex(layerHex); err != nil {
		return nil, fmt.Errorf("OCI manifest %s: layer digest %q: %w", reference, layer.Digest, err)
	}
	if layer.Size < 0 {
		return nil, fmt.Errorf("OCI manifest %s: layer size must not be negative (got %d)", reference, layer.Size)
	}
	return &OCIArtifact{
		ManifestDigest: manifestDigest,
		LayerSHA256:    layerHex,
		LayerSize:      layer.Size,
		layer:          layer,
	}, nil
}

// ResolveOCI resolves an oci:// source (tag, digest, or bare form; a
// bare reference defaults to the "latest" tag) to its manifest digest
// and wasm layer pin. It is the pinning operation for OCI sources: the
// returned ManifestDigest belongs in the source, LayerSHA256/LayerSize
// in the sha256/size fields.
func ResolveOCI(ctx context.Context, source string) (*OCIArtifact, error) {
	ref, err := parseOCISource(source)
	if err != nil {
		return nil, err
	}
	repo, err := ociRepository(ref)
	if err != nil {
		return nil, err
	}
	fctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	return fetchOCIManifest(fctx, repo, ref.ReferenceOrDefault())
}

// fetchOCI produces the verified wasm bytes for an oci:// entry. The
// source must be pinned to a manifest digest (strict validation
// guarantees this): the digest fixes the OCI manifest bytes, the
// manifest fixes the layer digest, and the downloaded blob is verified
// against that digest (and the entry's own sha256/size pins, when set)
// before it is cached or returned. Unverified bytes are never returned.
func (p *Plugin) fetchOCI(ctx context.Context, cacheDir string) ([]byte, error) {
	src := p.ResolvedSource()
	ref, err := parseOCISource(src)
	if err != nil {
		return nil, fmt.Errorf("plugin %q: %w", p.Name, err)
	}
	pinnedHex, err := ociSourceDigestHex(ref)
	if err != nil {
		return nil, fmt.Errorf("plugin %q: %w", p.Name, err)
	}
	if pinnedHex == "" {
		return nil, fmt.Errorf("plugin %q: OCI source %s is not pinned to a manifest digest (run `caddywit manifest pin`)", p.Name, src)
	}

	fctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()

	repo, err := ociRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("plugin %q: %w", p.Name, err)
	}
	art, err := fetchOCIManifest(fctx, repo, ref.Reference)
	if err != nil {
		return nil, fmt.Errorf("plugin %q: %w", p.Name, err)
	}
	if art.ManifestDigest != ociDigestPrefix+pinnedHex {
		// fetchOCIManifest already verified content against the resolved
		// digest, which the registry client matched to the request; this
		// re-check keeps the guarantee local and explicit.
		return nil, fmt.Errorf("plugin %q: OCI manifest digest %s does not match pinned %s (source %s)", p.Name, art.ManifestDigest, ociDigestPrefix+pinnedHex, src)
	}

	// Enforce the entry's own pins against the layer descriptor BEFORE
	// downloading the blob: the (digest-verified) manifest already tells
	// us what the layer must hash to and how big it is.
	if p.SHA256 != "" && p.SHA256 != art.LayerSHA256 {
		return nil, fmt.Errorf("plugin %q: wasm layer sha256 mismatch: manifest pins %s, OCI artifact declares %s (source %s)", p.Name, p.SHA256, art.LayerSHA256, src)
	}
	sizeCap := int64(MaxWasmSize)
	if p.Size > 0 {
		sizeCap = p.Size
		if art.LayerSize != p.Size {
			return nil, fmt.Errorf("plugin %q: size mismatch: manifest pins %d bytes, OCI artifact declares %d (source %s)", p.Name, p.Size, art.LayerSize, src)
		}
	}
	if art.LayerSize > sizeCap {
		return nil, fmt.Errorf("plugin %q: wasm layer of %d bytes exceeds %d byte limit (source %s)", p.Name, art.LayerSize, sizeCap, src)
	}

	// The layer digest is known before the download, so the content-
	// addressed cache can be consulted first.
	if cacheDir != "" {
		if data, ok := readCache(cacheDir, art.LayerSHA256); ok {
			return data, nil
		}
	}

	rc, err := repo.Blobs().Fetch(fctx, art.layer)
	if err != nil {
		return nil, fmt.Errorf("plugin %q: fetching wasm layer %s: %w", p.Name, art.layer.Digest, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, art.LayerSize+1))
	if err != nil {
		return nil, fmt.Errorf("plugin %q: reading wasm layer %s: %w", p.Name, art.layer.Digest, err)
	}
	if int64(len(data)) != art.LayerSize {
		return nil, fmt.Errorf("plugin %q: wasm layer size mismatch: OCI artifact declares %d bytes, got %d or more (source %s)", p.Name, art.LayerSize, len(data), src)
	}
	if got := HashBytes(data); got != art.LayerSHA256 {
		// Never cache or return bytes that do not hash to the layer
		// digest the (digest-pinned) OCI manifest declares.
		return nil, fmt.Errorf("plugin %q: wasm layer sha256 mismatch: OCI artifact declares %s, got %s (source %s)", p.Name, art.LayerSHA256, got, src)
	}
	if cacheDir != "" {
		// Best effort: a cache write failure must not fail the load.
		_ = writeCache(cacheDir, art.LayerSHA256, data)
	}
	return data, nil
}
