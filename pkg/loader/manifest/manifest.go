// Package manifest implements the caddy-wit plugin manifest: a JSON lock
// file (conventionally named caddy-wit.json) that pins every wasm plugin
// source to a sha256 hash. The loader refuses to feed any bytes to the
// wasm compiler unless they match the manifest, so the manifest is the
// integrity boundary for all dynamically loaded plugin code.
//
// This package is intentionally free of any dependency on the wasm
// runtime so that tools (cmd/caddywit) can link it without pulling in
// Caddy or wazero.
package manifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Version is the only manifest schema version this package understands.
const Version = 1

// Manifest is the parsed caddy-wit.json file: a schema version plus the
// list of pinned plugins.
type Manifest struct {
	Version int      `json:"version"`
	Plugins []Plugin `json:"plugins"`
}

// Plugin is one pinned plugin entry in a manifest.
type Plugin struct {
	// Name identifies the entry in diagnostics; it must be unique within
	// the manifest.
	Name string `json:"name"`

	// Source is an http(s) URL, an oci:// reference to a wasm OCI
	// artifact ("oci://<registry>/<repo>[:tag][@sha256:<hex>]"), or a
	// filesystem path. Relative paths are resolved against the manifest
	// file's directory at load time (see ResolvedSource).
	Source string `json:"source"`

	// Tag is a purely informational record of the OCI tag that was
	// pinned (e.g. "v1.2.0"). Only allowed on oci:// sources. `caddywit
	// manifest pin` re-resolves it to a possibly new digest; strict
	// loading ignores it entirely — only the manifest digest in Source
	// is trusted.
	Tag string `json:"tag,omitempty"`

	// SHA256 is the hex-encoded sha256 of the wasm bytes. Required for
	// URL sources always, and for filesystem sources unless
	// InsecureSkipVerify is set. Optional for oci:// sources (there the
	// manifest digest in Source is the pin); when set on an oci:// entry
	// it additionally pins the wasm layer bytes.
	SHA256 string `json:"sha256,omitempty"`

	// Size, when non-zero, is the exact byte length the wasm must have.
	// It also caps how many bytes are downloaded for URL sources.
	Size int64 `json:"size,omitempty"`

	// Modules, when non-nil, is an allowlist of Caddy module IDs the
	// plugin may register. Anything extra the plugin declares is an
	// error.
	Modules []string `json:"modules,omitempty"`

	// Permissions is the list of host capabilities granted to this
	// plugin. Valid values are "http" (the caddy:plugin/host-http
	// outbound HTTP client) and "tcp" (caddy:plugin/host-tcp raw TCP
	// connections); anything else, or a duplicate, is a validation
	// error. The default is no network access: a plugin's WIT imports
	// for host-http/host-tcp fail unless the matching permission is
	// listed here.
	//
	// Together with the sha256 pin this is the manifest's trust model:
	// the hash pins exactly which code runs, and permissions pin what
	// that code is allowed to reach. Granting "http"/"tcp" is an
	// explicit, reviewable decision recorded in the lock file.
	Permissions []string `json:"permissions,omitempty"`

	// InsecureSkipVerify skips the hash check for this entry. It is only
	// allowed for filesystem sources and is intended for local dev
	// iteration where the wasm is rebuilt constantly.
	//
	// It deliberately does NOT apply to URL sources: remote content is
	// mutable and unauthenticated — the server (or anyone between us and
	// it, or a compromised CDN/mirror) can serve different bytes on every
	// request, so a URL without a pinned hash gives no integrity
	// guarantee at all. A URL source without sha256 is therefore always a
	// hard error.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	// resolvedSource is Source with relative filesystem paths made
	// absolute against the manifest's directory. Set by Load /
	// LoadEditable; empty for entries constructed by hand.
	resolvedSource string
}

// ResolvedSource returns the source to actually fetch from: the absolute
// path computed at load time for relative filesystem sources, otherwise
// Source as written.
func (p *Plugin) ResolvedSource() string {
	if p.resolvedSource != "" {
		return p.resolvedSource
	}
	return p.Source
}

// IsURL reports whether source is an http(s) URL rather than a
// filesystem path.
func IsURL(source string) bool {
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

// ResolveSource resolves a manifest source against the directory of the
// manifest file: URLs, oci:// references, and absolute paths are
// returned unchanged, relative paths are joined to manifestDir.
func ResolveSource(manifestDir, source string) string {
	if IsURL(source) || IsOCI(source) || filepath.IsAbs(source) {
		return source
	}
	return filepath.Join(manifestDir, source)
}

// Load reads, parses, and fully validates the manifest at path. Every
// entry must satisfy the pinning rules (see validate); relative
// filesystem sources are resolved against the manifest's directory.
func Load(path string) (*Manifest, error) {
	return load(path, true)
}

// LoadEditable is Load with the pinning rules relaxed: entries may lack
// sha256 (e.g. a hand-written manifest that has not been pinned yet).
// It is meant for tools that are about to fill in the hashes; never load
// plugins from an editable manifest.
func LoadEditable(path string) (*Manifest, error) {
	return load(path, false)
}

func load(path string, strict bool) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	// Reject unknown fields: a typo in a security-relevant field (say,
	// a misspelled sha256) must not silently disable a check.
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parsing manifest %s: %w", path, err)
	}
	if err := m.validate(strict); err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	for i := range m.Plugins {
		m.Plugins[i].resolvedSource = ResolveSource(dir, m.Plugins[i].Source)
	}
	return &m, nil
}

// validate checks the structural rules. When strict, the pinning rules
// are enforced too: URL sources must carry sha256, and filesystem
// sources must carry sha256 unless insecure_skip_verify is set.
func (m *Manifest) validate(strict bool) error {
	var errs []error
	if m.Version != Version {
		errs = append(errs, fmt.Errorf("unsupported manifest version %d (this build supports version %d)", m.Version, Version))
	}
	seen := make(map[string]bool, len(m.Plugins))
	for i := range m.Plugins {
		p := &m.Plugins[i]
		ref := fmt.Sprintf("plugins[%d]", i)
		if p.Name != "" {
			ref = fmt.Sprintf("plugin %q", p.Name)
		}
		if p.Name == "" {
			errs = append(errs, fmt.Errorf("%s: name is required", ref))
		} else if seen[p.Name] {
			errs = append(errs, fmt.Errorf("%s: duplicate name", ref))
		}
		seen[p.Name] = true

		if p.Source == "" {
			errs = append(errs, fmt.Errorf("%s: source is required", ref))
		}
		if p.SHA256 != "" {
			if err := checkSHA256Hex(p.SHA256); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", ref, err))
			} else {
				p.SHA256 = strings.ToLower(p.SHA256)
			}
		}
		if p.Size < 0 {
			errs = append(errs, fmt.Errorf("%s: size must not be negative (got %d)", ref, p.Size))
		}
		if err := CheckPermissions(p.Permissions); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ref, err))
		}
		isURL := IsURL(p.Source)
		isOCI := IsOCI(p.Source)
		if isURL && p.InsecureSkipVerify {
			// See the InsecureSkipVerify doc comment: remote content is
			// mutable and unauthenticated, so skipping verification for a
			// URL source is never acceptable.
			errs = append(errs, fmt.Errorf("%s: insecure_skip_verify is only allowed for filesystem sources, not URL %q", ref, p.Source))
		}
		if isOCI {
			if err := p.validateOCI(strict, ref); err != nil {
				errs = append(errs, err)
			}
		} else if p.Tag != "" {
			errs = append(errs, fmt.Errorf("%s: tag is only allowed for oci:// sources, not %q", ref, p.Source))
		}
		if strict && p.SHA256 == "" && !isOCI {
			switch {
			case isURL:
				errs = append(errs, fmt.Errorf("%s: URL source %q requires a pinned sha256 (remote content is mutable and unauthenticated; run `caddywit manifest pin`)", ref, p.Source))
			case !p.InsecureSkipVerify:
				errs = append(errs, fmt.Errorf("%s: sha256 is required unless insecure_skip_verify is set (run `caddywit manifest pin`)", ref))
			}
		}
	}
	return errors.Join(errs...)
}

// Permission values accepted in Plugin.Permissions. Each one gates the
// corresponding caddy:plugin host import (see the Permissions field doc).
const (
	// PermissionHTTP grants the outbound HTTP client (host-http).
	PermissionHTTP = "http"
	// PermissionTCP grants raw TCP connections (host-tcp).
	PermissionTCP = "tcp"
)

// CheckPermissions validates a Plugin.Permissions list: every entry must
// be one of the Permission* constants and appear at most once.
func CheckPermissions(perms []string) error {
	var errs []error
	seen := make(map[string]bool, len(perms))
	for _, perm := range perms {
		switch perm {
		case PermissionHTTP, PermissionTCP:
		default:
			errs = append(errs, fmt.Errorf("unknown permission %q (valid permissions: %q, %q)", perm, PermissionHTTP, PermissionTCP))
			continue
		}
		if seen[perm] {
			errs = append(errs, fmt.Errorf("duplicate permission %q", perm))
		}
		seen[perm] = true
	}
	return errors.Join(errs...)
}

// checkSHA256Hex validates a hex-encoded sha256 digest.
func checkSHA256Hex(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("sha256 must be 64 hex characters, got %d", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("sha256 is not valid hex: %w", err)
	}
	return nil
}

// Save writes the manifest to path as pretty-printed JSON (2-space
// indent, stable field order, trailing newline).
func (m *Manifest) Save(path string) error {
	if m.Plugins == nil {
		m.Plugins = []Plugin{} // marshal as [] rather than null
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing manifest: %w", err)
	}
	return nil
}
