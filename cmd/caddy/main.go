// Command caddy is a custom Caddy binary with caddy-wit compiled in.
// It is equivalent to
//
//	xcaddy build --with github.com/elee1766/caddy-wit/pkg/loader
//
// plus the `caddy wasm` CLI extension: all standard Caddy modules, the
// caddy-wit plugin loader (which loads manifest-pinned wasm plugins
// from the file named by the CADDY_WIT_MANIFEST environment variable
// at startup), and the `caddy wasm manifest ...` commands for managing
// those manifests.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// All standard Caddy modules.
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// `caddy wasm ...` CLI extension.
	_ "github.com/elee1766/caddy-wit/pkg/caddycli"
	// Wasm plugin loading via CADDY_WIT_MANIFEST.
	_ "github.com/elee1766/caddy-wit/pkg/loader"
)

func main() {
	caddycmd.Main()
}
