package manifest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	// MaxWasmSize caps how many bytes are read for a single plugin
	// binary, from any source, unless the entry pins a smaller size.
	MaxWasmSize = 512 << 20 // 512 MiB

	// FetchTimeout bounds a single plugin download.
	FetchTimeout = 30 * time.Second

	// CacheDirEnvVar overrides where downloaded plugins are cached.
	CacheDirEnvVar = "CADDY_WIT_CACHE"
)

// HashBytes returns the hex-encoded sha256 of data.
func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CacheDir returns the download cache directory: $CADDY_WIT_CACHE if
// set, else <user cache dir>/caddy-wit.
func CacheDir() (string, error) {
	if dir := os.Getenv(CacheDirEnvVar); dir != "" {
		return dir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("determining user cache dir (set %s to override): %w", CacheDirEnvVar, err)
	}
	return filepath.Join(base, "caddy-wit"), nil
}

// FetchSource reads raw wasm bytes from a filesystem path or an http(s)
// URL, with no verification and no caching. sizeCap <= 0 means
// MaxWasmSize. Callers loading plugins must verify the result against
// the manifest entry before using it. oci:// sources are not supported
// here: their verification is inseparable from fetching (the manifest
// digest pins the layer), so they must go through Plugin.Fetch or
// ResolveOCI.
func FetchSource(ctx context.Context, source string, sizeCap int64) ([]byte, error) {
	if sizeCap <= 0 {
		sizeCap = MaxWasmSize
	}
	if IsOCI(source) {
		return nil, fmt.Errorf("oci:// source %s must be fetched through a manifest entry (Plugin.Fetch) or resolved with ResolveOCI", source)
	}
	if IsURL(source) {
		return fetchURL(ctx, source, sizeCap)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > sizeCap {
		return nil, fmt.Errorf("file %s exceeds %d byte limit", source, sizeCap)
	}
	return data, nil
}

// fetchURL downloads url with a timeout and a hard size cap.
func fetchURL(ctx context.Context, url string, sizeCap int64) ([]byte, error) {
	fctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: unexpected HTTP status %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, sizeCap+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if int64(len(data)) > sizeCap {
		return nil, fmt.Errorf("GET %s: response exceeds %d byte limit", url, sizeCap)
	}
	return data, nil
}

// Verify checks data against the entry's pins: the sha256 hash (unless
// InsecureSkipVerify is set) and, when pinned, the exact size.
func (p *Plugin) Verify(data []byte) error {
	if p.Size > 0 && int64(len(data)) != p.Size {
		return fmt.Errorf("plugin %q: size mismatch: manifest pins %d bytes, got %d (source %s)",
			p.Name, p.Size, len(data), p.ResolvedSource())
	}
	if p.InsecureSkipVerify {
		return nil
	}
	return p.VerifyHash(data)
}

// VerifyHash checks data against the pinned sha256, regardless of
// InsecureSkipVerify. Used by `caddywit manifest verify` so that a
// pinned hash, when present, is always actually checked.
func (p *Plugin) VerifyHash(data []byte) error {
	got := HashBytes(data)
	if got != p.SHA256 {
		return fmt.Errorf("plugin %q: sha256 mismatch: manifest pins %s, got %s (source %s)",
			p.Name, p.SHA256, got, p.ResolvedSource())
	}
	return nil
}

// Fetch produces the verified wasm bytes for the entry. Filesystem
// sources are read directly; URL and oci:// sources are served from the
// content-addressed cache in cacheDir when possible and downloaded (then
// verified, then cached) otherwise. Pass cacheDir == "" to disable
// caching.
//
// Fetch never returns unverified bytes: any hash or size mismatch is an
// error and nothing may be compiled from this entry.
func (p *Plugin) Fetch(ctx context.Context, cacheDir string) ([]byte, error) {
	src := p.ResolvedSource()
	sizeCap := int64(MaxWasmSize)
	if p.Size > 0 {
		sizeCap = p.Size
	}

	if IsOCI(src) {
		return p.fetchOCI(ctx, cacheDir)
	}

	if !IsURL(src) {
		data, err := os.ReadFile(src)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: reading %s: %w", p.Name, src, err)
		}
		if int64(len(data)) > int64(MaxWasmSize) {
			return nil, fmt.Errorf("plugin %q: file %s exceeds %d byte limit", p.Name, src, int64(MaxWasmSize))
		}
		if err := p.Verify(data); err != nil {
			return nil, err
		}
		return data, nil
	}

	// URL source: validation guarantees a pinned sha256, so the cache
	// can be keyed by content hash.
	if cacheDir != "" && p.SHA256 != "" {
		if data, ok := readCache(cacheDir, p.SHA256); ok {
			return data, nil
		}
	}
	data, err := fetchURL(ctx, src, sizeCap)
	if err != nil {
		return nil, fmt.Errorf("plugin %q: %w", p.Name, err)
	}
	if err := p.Verify(data); err != nil {
		return nil, err
	}
	if cacheDir != "" && p.SHA256 != "" {
		// Best effort: a cache write failure must not fail the load.
		_ = writeCache(cacheDir, p.SHA256, data)
	}
	return data, nil
}

// cachePath returns the content-addressed cache file for a hash.
func cachePath(dir, hash string) string {
	return filepath.Join(dir, "sha256-"+hash+".wasm")
}

// readCache returns the cached bytes for hash if present and intact.
// The bytes are re-hashed on every hit as a defense against cache
// tampering or corruption; a mismatching file is deleted so the caller
// falls through to a fresh download.
func readCache(dir, hash string) ([]byte, bool) {
	path := cachePath(dir, hash)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	if HashBytes(data) != hash {
		os.Remove(path)
		return nil, false
	}
	return data, true
}

// writeCache stores verified bytes under their content hash, atomically
// (temp file + rename) so a crash never leaves a partial file at the
// final path.
func writeCache(dir, hash string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sha256-"+hash+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, cachePath(dir, hash))
}
