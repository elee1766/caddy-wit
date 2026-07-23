package loader

import (
	"context"
	"fmt"
	"os"
	"time"
)

// ManifestEnvVar names the environment variable that points at the
// plugin manifest file (conventionally caddy-wit.json).
const ManifestEnvVar = "CADDY_WIT_MANIFEST"

// legacyPluginsEnvVar is the pre-manifest discovery variable. It loaded
// executable code from bare directories and URLs with no integrity
// checking, so it is now rejected rather than honored.
const legacyPluginsEnvVar = "CADDY_WIT_PLUGINS"

// bootLoader keeps the process-lifetime loader (and its wasm runtime, and
// every compiled plugin) reachable after init.
var bootLoader *Loader

// init bootstraps wasm plugins from the manifest file named by the
// CADDY_WIT_MANIFEST environment variable. Only manifest-pinned plugins
// are loaded: every entry's wasm bytes must match its sha256 (and size,
// when pinned) before they are compiled.
//
// WHY INIT-TIME REGISTRATION?
//
// caddy.RegisterModule must be called before Caddy loads or parses any
// config: module lookup (JSON module maps, Caddyfile directive resolution,
// `caddy list-modules`, ...) reads the global module registry, which is
// populated at package-init time by every compiled-in plugin. A dynamic
// wasm module therefore cannot be registered during provisioning — by the
// time any module's Provision runs, the config referencing our modules has
// already been resolved against the registry and would have failed. That
// leaves process startup as the only registration window, and an
// environment variable as the only config channel available that early.
// This env-var bootstrap is the current mechanism; a Caddyfile global
// option or a JSON app that triggers a re-exec/re-scan (so the manifest
// path can live in normal config) is future work.
//
// Failure policy: a broken manifest or plugin (or an unset runtime) must
// not prevent Caddy from starting — errors are logged to stderr and
// startup continues; only the referenced wasm modules will be missing
// (and config referring to them will fail with "module not registered",
// pointing at the cause).
func init() {
	if os.Getenv(legacyPluginsEnvVar) != "" {
		fmt.Fprintf(os.Stderr,
			"caddy-wit: %s is no longer supported and is ignored: loading plugins from bare directories/URLs had no integrity checking. Set %s to a caddy-wit.json manifest with pinned sha256 hashes instead (create one with `caddywit manifest init` / `caddywit manifest add`).\n",
			legacyPluginsEnvVar, ManifestEnvVar)
	}

	path := os.Getenv(ManifestEnvVar)
	if path == "" {
		return
	}

	// This context bounds only fetching/compilation/registration calls;
	// compiled plugins and the runtime live for the rest of the process.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	l, err := New(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "caddy-wit: creating wasm runtime failed, no plugins loaded: %v\n", err)
		return
	}
	bootLoader = l

	if err := l.LoadManifest(ctx, path); err != nil {
		fmt.Fprintf(os.Stderr, "caddy-wit: plugin load errors (continuing startup): %v\n", err)
	}
}
