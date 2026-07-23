//go:build tinygo || wasm

package defaults

import (
	"go.bytecodealliance.org/cm"

	"github.com/elee1766/caddy-wit/sdk/go/gen/caddy/plugin/config"
	"github.com/elee1766/caddy-wit/sdk/go/gen/caddy/plugin/lifecycle"
)

func init() {
	// Lifecycle: Destructor already defaults to no-op in the generated code
	// (lifecycle.wit.go). Set the rest.
	if lifecycle.Exports.Instance.Validate == nil {
		lifecycle.Exports.Instance.Validate = func(self cm.Rep) cm.Result[string, struct{}, string] {
			return cm.OK[cm.Result[string, struct{}, string]](struct{}{})
		}
	}
	if lifecycle.Exports.Instance.Cleanup == nil {
		lifecycle.Exports.Instance.Cleanup = func(self cm.Rep) {}
	}

	// Config: if no Caddyfile support, return an empty JSON object so the
	// module is still configurable via JSON.
	if config.Exports.UnmarshalCaddyfile == nil {
		config.Exports.UnmarshalCaddyfile = func(moduleID string, tokens cm.List[config.Token]) cm.Result[string, config.JSON, string] {
			return cm.OK[cm.Result[string, config.JSON, string]]("{}")
		}
	}
}
