// Package manifestcli implements the caddy-wit manifest management
// operations shared by the standalone caddywit CLI (cmd/caddywit) and
// the `caddy wasm manifest` command group (caddycli): creating,
// extending, pinning, and verifying plugin manifests — JSON lock files
// that pin wasm plugin sources to sha256 hashes, consumed by the Caddy
// loader (github.com/elee1766/caddy-wit/pkg/loader) via the
// CADDY_WIT_MANIFEST environment variable.
//
// Each operation is a small exported function taking explicit inputs
// and an io.Writer for its report; callers own argv parsing, error
// formatting, and exit codes.
package manifestcli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/elee1766/caddy-wit/pkg/loader/manifest"
)

// Init writes an empty version-1 manifest at path, refusing to
// overwrite an existing file.
func Init(out io.Writer, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing manifest %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking %s: %w", path, err)
	}
	m := &manifest.Manifest{Version: manifest.Version, Plugins: []manifest.Plugin{}}
	if err := m.Save(path); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote empty manifest %s\n", path)
	return nil
}

// Add fetches source (a filesystem path, an http(s) URL, or an oci://
// reference; relative paths resolve against the manifest's directory),
// computes its sha256 and size, and appends a pinned entry to the
// manifest at path. OCI sources are stored digest-pinned with the
// resolved tag recorded in the entry's tag field.
//
// name is the entry name; when empty it defaults to the source basename
// without the .wasm extension. permissions is a comma-separated list of
// host capabilities to grant ("http", "tcp"); empty grants none.
func Add(out io.Writer, path, source, name, permissions string) error {
	ctx := context.Background()

	perms, err := parsePermissions(permissions)
	if err != nil {
		return err
	}

	m, err := manifest.LoadEditable(path)
	if err != nil {
		return err
	}

	entryName := name
	if entryName == "" {
		entryName, err = defaultName(source)
		if err != nil {
			return fmt.Errorf("cannot derive a name from source %q (use -name): %w", source, err)
		}
	}
	for i := range m.Plugins {
		if m.Plugins[i].Name == entryName {
			return fmt.Errorf("manifest already has an entry named %q", entryName)
		}
		if m.Plugins[i].Source == source {
			return fmt.Errorf("manifest already has an entry for source %q (name %q)", source, m.Plugins[i].Name)
		}
	}

	var entry manifest.Plugin
	if manifest.IsOCI(source) {
		// OCI sources are stored pinned: the tag (if any) is resolved to
		// a manifest digest and moved to the informational tag field.
		entry, err = resolveOCIEntry(ctx, source)
		if err != nil {
			return err
		}
		entry.Name = entryName
		for i := range m.Plugins {
			if m.Plugins[i].Source == entry.Source {
				return fmt.Errorf("manifest already has an entry for source %q (name %q)", entry.Source, m.Plugins[i].Name)
			}
		}
	} else {
		// Fetch from the same location the loader will: relative
		// filesystem paths resolve against the manifest's directory.
		resolved := manifest.ResolveSource(filepath.Dir(path), source)
		data, err := manifest.FetchSource(ctx, resolved, 0)
		if err != nil {
			return fmt.Errorf("fetching %s: %w", resolved, err)
		}
		entry = manifest.Plugin{
			Name:   entryName,
			Source: source,
			SHA256: manifest.HashBytes(data),
			Size:   int64(len(data)),
		}
	}
	entry.Permissions = perms
	m.Plugins = append(m.Plugins, entry)
	if err := m.Save(path); err != nil {
		return err
	}
	fmt.Fprintf(out, "added %q: %s (%d bytes, sha256 %s, permissions: %s)\n",
		entryName, entry.Source, entry.Size, entry.SHA256, permissionsLabel(entry.Permissions))
	return nil
}

// Pin (re)fetches every entry's source in the manifest at path and
// fills/updates its sha256 and size. OCI entries with a tag are
// re-resolved to the tag's current (possibly new) manifest digest and
// their source rewritten; digest-only OCI entries are checked for
// reachability and their sha256/size refreshed. It is all-or-nothing:
// if any source fails to fetch, nothing is written.
func Pin(out io.Writer, path string) error {
	ctx := context.Background()
	m, err := manifest.LoadEditable(path)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	var errs []error
	for i := range m.Plugins {
		p := &m.Plugins[i]
		if manifest.IsOCI(p.Source) {
			if err := pinOCIEntry(ctx, p); err != nil {
				errs = append(errs, fmt.Errorf("plugin %q: %w", p.Name, err))
			}
			continue
		}
		resolved := manifest.ResolveSource(dir, p.Source)
		data, err := manifest.FetchSource(ctx, resolved, 0)
		if err != nil {
			errs = append(errs, fmt.Errorf("plugin %q: fetching %s: %w", p.Name, resolved, err))
			continue
		}
		p.SHA256 = manifest.HashBytes(data)
		p.Size = int64(len(data))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("manifest not updated:\n%w", err)
	}
	if err := m.Save(path); err != nil {
		return err
	}
	for i := range m.Plugins {
		p := &m.Plugins[i]
		fmt.Fprintf(out, "pinned %q: %s (%d bytes, sha256 %s)\n", p.Name, p.Source, p.Size, p.SHA256)
	}
	return nil
}

// Verify fetches every entry's source in the manifest at path and
// checks the pinned sha256 and size, printing a per-entry report to
// out. OCI entries are fully verified: pinned manifest digest, wasm
// artifact media types, layer digest, and the optional sha256/size
// layer pins. It returns a non-nil error when the manifest itself
// cannot be loaded or when any entry fails verification; the caller
// decides the exit code.
func Verify(out io.Writer, path string) error {
	return VerifyStreams(out, out, path)
}

// VerifyStreams is Verify with per-entry successes reported to out and
// failures reported to errOut, for callers with distinct stdout/stderr
// streams.
func VerifyStreams(out, errOut io.Writer, path string) error {
	ctx := context.Background()
	// Strict load: a manifest the loader would reject (e.g. an unpinned
	// URL source) must also fail verification.
	m, err := manifest.Load(path)
	if err != nil {
		return err
	}

	var failed bool
	for i := range m.Plugins {
		p := &m.Plugins[i]
		resolved := p.ResolvedSource()
		if manifest.IsOCI(p.Source) {
			// Fetch performs the full OCI verification chain: pinned
			// manifest digest, wasm artifact media types, layer digest,
			// and the optional sha256/size layer pins. Caching is
			// disabled so the registry content is actually re-checked.
			data, ferr := p.Fetch(ctx, "")
			if ferr != nil {
				failed = true
				fmt.Fprintf(errOut, "FAIL %s: %v\n", p.Name, ferr)
				continue
			}
			fmt.Fprintf(out, "ok   %s: %s (%d bytes, sha256 %s, permissions: %s)\n",
				p.Name, p.Source, len(data), manifest.HashBytes(data), permissionsLabel(p.Permissions))
			continue
		}
		data, ferr := manifest.FetchSource(ctx, resolved, 0)
		if ferr != nil {
			failed = true
			fmt.Fprintf(errOut, "FAIL %s: fetching %s: %v\n", p.Name, resolved, ferr)
			continue
		}
		if p.SHA256 == "" {
			// Only reachable with insecure_skip_verify on a filesystem
			// source: there is nothing to verify against.
			fmt.Fprintf(out, "skip %s: no sha256 pinned (insecure_skip_verify, permissions: %s)\n",
				p.Name, permissionsLabel(p.Permissions))
			continue
		}
		// Check the pinned hash even if insecure_skip_verify is set:
		// this command's whole purpose is verification.
		var entryErrs []error
		if herr := p.VerifyHash(data); herr != nil {
			entryErrs = append(entryErrs, herr)
		}
		if p.Size > 0 && int64(len(data)) != p.Size {
			entryErrs = append(entryErrs, fmt.Errorf("plugin %q: size mismatch: manifest pins %d bytes, got %d (source %s)",
				p.Name, p.Size, len(data), resolved))
		}
		if len(entryErrs) > 0 {
			failed = true
			fmt.Fprintf(errOut, "FAIL %s: %v\n", p.Name, errors.Join(entryErrs...))
			continue
		}
		fmt.Fprintf(out, "ok   %s: %s (%d bytes, sha256 %s, permissions: %s)\n",
			p.Name, p.Source, len(data), p.SHA256, permissionsLabel(p.Permissions))
	}
	if failed {
		return fmt.Errorf("manifest verification failed for %s", path)
	}
	return nil
}

// parsePermissions parses a comma-separated list of permission names
// ("http", "tcp"), validated with the same rules the manifest loader
// applies. An empty string means no permissions.
func parsePermissions(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	perms := strings.Split(s, ",")
	for i := range perms {
		perms[i] = strings.TrimSpace(perms[i])
	}
	if err := manifest.CheckPermissions(perms); err != nil {
		return nil, fmt.Errorf("-permissions: %w", err)
	}
	return perms, nil
}

// permissionsLabel renders an entry's granted permissions for output:
// "none" when nothing is granted.
func permissionsLabel(perms []string) string {
	if len(perms) == 0 {
		return "none"
	}
	return strings.Join(perms, ",")
}

// resolveOCIEntry resolves an oci:// source (tag, digest, or bare form)
// into a fully pinned entry: a digest-pinned source, the informational
// tag that was resolved (a bare reference resolves to "latest"), and the
// wasm layer digest/size in sha256/size.
func resolveOCIEntry(ctx context.Context, source string) (manifest.Plugin, error) {
	art, err := manifest.ResolveOCI(ctx, source)
	if err != nil {
		return manifest.Plugin{}, fmt.Errorf("resolving %s: %w", source, err)
	}
	pinned, err := manifest.PinnedOCISource(source, art.ManifestDigest)
	if err != nil {
		return manifest.Plugin{}, err
	}
	tag := manifest.OCITag(source)
	if tag == "" && !strings.Contains(source, "@") {
		tag = "latest" // what a bare reference resolves to
	}
	return manifest.Plugin{
		Source: pinned,
		Tag:    tag,
		SHA256: art.LayerSHA256,
		Size:   art.LayerSize,
	}, nil
}

// pinOCIEntry re-pins one oci:// entry in place. Entries with a tag —
// from the tag field or written directly in the source — are re-resolved
// to the tag's current (possibly new) manifest digest, rewriting the
// source to its pinned form. Digest-only entries are re-resolved by
// digest, which verifies the artifact is still reachable and intact and
// refreshes the sha256/size layer pins.
func pinOCIEntry(ctx context.Context, p *manifest.Plugin) error {
	tag := p.Tag
	if tag == "" {
		tag = manifest.OCITag(p.Source)
	}
	target := p.Source
	if tag != "" {
		base, err := manifest.OCIRepositorySource(p.Source)
		if err != nil {
			return err
		}
		target = base + ":" + tag
	}
	entry, err := resolveOCIEntry(ctx, target)
	if err != nil {
		return err
	}
	p.Source = entry.Source
	p.Tag = entry.Tag
	p.SHA256 = entry.SHA256
	p.Size = entry.Size
	return nil
}

// defaultName derives an entry name from a source: its basename without
// the .wasm extension. For oci:// sources this is the last path element
// of the repository (tag and digest stripped).
func defaultName(source string) (string, error) {
	base := source
	switch {
	case manifest.IsOCI(source):
		repo, err := manifest.OCIRepositorySource(source)
		if err != nil {
			return "", err
		}
		base = path.Base(strings.TrimPrefix(repo, "oci://"))
	case manifest.IsURL(source):
		u, err := url.Parse(source)
		if err != nil {
			return "", err
		}
		base = path.Base(u.Path)
	default:
		base = filepath.Base(source)
	}
	name := strings.TrimSuffix(base, ".wasm")
	if name == "" || name == "." || name == "/" || name == string(filepath.Separator) {
		return "", fmt.Errorf("source has no usable basename")
	}
	return name, nil
}
