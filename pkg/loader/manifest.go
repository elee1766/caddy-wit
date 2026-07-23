package loader

import "github.com/elee1766/caddy-wit/pkg/loader/manifest"

// Manifest is the parsed caddy-wit.json plugin lock file: a schema
// version plus a list of plugin entries, each pinning a wasm source to a
// sha256 hash.
//
// The format, validation rules, and fetch/verify/cache logic live in the
// loader/manifest subpackage (which is free of runtime dependencies so
// cmd/caddywit can link it); the types are aliased here so that package
// loader presents the whole manifest API.
type Manifest = manifest.Manifest

// ManifestPlugin is one pinned plugin entry in a Manifest.
type ManifestPlugin = manifest.Plugin

// LoadManifest reads, parses, and validates the manifest file at path.
// Validation enforces: version == 1, unique plugin names, non-empty
// sources, well-formed 64-hex sha256 values, a pinned sha256 for every
// URL source, and a pinned @sha256: manifest digest for every oci://
// source (insecure_skip_verify never applies to URLs or OCI references —
// remote content is mutable and unauthenticated). Relative filesystem
// sources are resolved against the manifest file's directory.
func LoadManifest(path string) (*Manifest, error) {
	return manifest.Load(path)
}
