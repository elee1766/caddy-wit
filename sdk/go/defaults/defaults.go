// Package defaults sets safe no-op defaults for all optional caddy:plugin
// exports. Import it with _ to make lifecycle.Cleanup, lifecycle.Validate,
// config.UnmarshalCaddyfile, and other non-essential exports no-ops instead
// of nil-pointer panics.
//
// Plugins only need to assign the exports they actually implement.
//
// Usage:
//
//	import _ "github.com/elee1766/caddy-wit/sdk/go/defaults"
package defaults
