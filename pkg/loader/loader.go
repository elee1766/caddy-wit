// Package loader compiles and registers wasm plugins as Caddy modules,
// strictly from a manifest file with pinned sha256 hashes.
//
// Consuming builds enable it with a blank import:
//
//	import _ "github.com/elee1766/caddy-wit/pkg/loader"
//
// e.g. via `xcaddy build --with github.com/elee1766/caddy-wit/pkg/loader`, and
// point CADDY_WIT_MANIFEST at a caddy-wit.json manifest (see bootstrap.go).
// Manifests are created and pinned with the cmd/caddywit tool.
package loader

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/elee1766/caddy-wit/pkg/loader/manifest"
	"github.com/elee1766/caddy-wit/pkg/runtime"
	"github.com/elee1766/caddy-wit/pkg/shim"
)

// Loader compiles wasm plugin binaries on a shared runtime and registers
// their declared Caddy modules through the shim package.
type Loader struct {
	rt      *runtime.Runtime
	plugins []*shim.LoadedPlugin
}

// New creates a Loader with a fresh wasm runtime.
func New(ctx context.Context) (*Loader, error) {
	rt, err := runtime.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating wasm runtime: %w", err)
	}
	return &Loader{rt: rt}, nil
}

// Plugins returns the plugins that registered at least one Caddy module.
func (l *Loader) Plugins() []*shim.LoadedPlugin { return l.plugins }

// LoadManifest loads the manifest at manifestPath and, for each entry,
// fetches the wasm bytes, verifies them against the pinned sha256/size,
// compiles the plugin, and registers every Caddy module it declares
// (subject to the entry's optional module allowlist).
//
// Per-plugin failures are aggregated with errors.Join and do not abort
// the other plugins. A plugin that fails verification is never compiled:
// unverified bytes are never handed to the wasm compiler.
func (l *Loader) LoadManifest(ctx context.Context, manifestPath string) error {
	m, err := manifest.Load(manifestPath)
	if err != nil {
		return err
	}

	// The download cache is an optimization; if no cache dir can be
	// determined, load without one.
	cacheDir, err := manifest.CacheDir()
	if err != nil {
		log.Printf("caddy-wit: plugin download cache disabled: %v", err)
		cacheDir = ""
	}

	var errs []error
	for i := range m.Plugins {
		entry := &m.Plugins[i]
		// Fetch verifies hash and size; on any mismatch it returns an
		// error and the bytes below never exist, so nothing unverified
		// can reach CompilePlugin.
		wasm, err := entry.Fetch(ctx, cacheDir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := l.loadPlugin(ctx, entry, wasm); err != nil {
			errs = append(errs, fmt.Errorf("plugin %q (source %s): %w", entry.Name, entry.ResolvedSource(), err))
		}
	}
	return errors.Join(errs...)
}

// loadPlugin compiles one verified wasm binary, queries its module
// declarations, enforces the manifest entry's allowlist, and registers
// each declared Caddy module. Per-module registration errors are
// aggregated so one bad declaration doesn't sink its siblings.
func (l *Loader) loadPlugin(ctx context.Context, entry *manifest.Plugin, wasm []byte) error {
	p, err := l.rt.CompilePlugin(ctx, wasm)
	if err != nil {
		return fmt.Errorf("compiling: %w", err)
	}
	info, err := p.Info(ctx)
	if err != nil {
		return fmt.Errorf("querying plugin manifest: %w", err)
	}
	if len(info.Modules) == 0 {
		return fmt.Errorf("plugin declares no Caddy modules")
	}

	if entry.Modules != nil {
		declared := make([]string, len(info.Modules))
		for i, d := range info.Modules {
			declared[i] = d.ID
		}
		if extra := disallowedModules(entry.Modules, declared); len(extra) > 0 {
			return fmt.Errorf("declares Caddy modules not in the manifest allowlist: %s (allowed: %s)",
				strings.Join(extra, ", "), strings.Join(entry.Modules, ", "))
		}
	}

	lp := &shim.LoadedPlugin{
		Name:        info.Name,
		Plugin:      p,
		Caps:        p.Capabilities(),
		Permissions: permissionsFromManifest(entry.Permissions),
	}

	var errs []error
	var registered []string
	for _, decl := range info.Modules {
		if err := shim.Register(lp, decl); err != nil {
			errs = append(errs, err)
			continue
		}
		registered = append(registered, decl.ID)
	}

	if len(registered) > 0 {
		l.plugins = append(l.plugins, lp)
		// TODO: use a zap logger once one is plumbed through; module
		// registration happens before Caddy's logging is configured.
		log.Printf("caddy-wit: plugin %q v%s (%s): registered modules %v",
			info.Name, info.Version, entry.ResolvedSource(), registered)
	}
	return errors.Join(errs...)
}

// permissionsFromManifest converts a manifest entry's validated
// permissions list (see manifest.Plugin.Permissions) into the runtime's
// Permissions flags. Unknown values are ignored here because manifest
// validation already rejected them; the zero value (no permissions
// listed) grants no network access.
func permissionsFromManifest(perms []string) runtime.Permissions {
	var p runtime.Permissions
	for _, perm := range perms {
		switch perm {
		case manifest.PermissionHTTP:
			p.HTTP = true
		case manifest.PermissionTCP:
			p.TCP = true
		}
	}
	return p
}

// disallowedModules returns the declared module IDs that are absent from
// the allowlist, preserving declaration order.
func disallowedModules(allow, declared []string) []string {
	allowed := make(map[string]bool, len(allow))
	for _, id := range allow {
		allowed[id] = true
	}
	var extra []string
	for _, id := range declared {
		if !allowed[id] {
			extra = append(extra, id)
		}
	}
	return extra
}
