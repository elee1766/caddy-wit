package shim

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/elee1766/caddy-wit/pkg/runtime"
)

// HTTPHandler adapts a wasm plugin module in the http.handlers.* namespace
// to caddyhttp.MiddlewareHandler.
type HTTPHandler struct {
	shimCore
}

func newHTTPHandler(lp *LoadedPlugin, moduleID string) *HTTPHandler {
	return &HTTPHandler{shimCore{lp: lp, moduleID: moduleID}}
}

// CaddyModule returns the Caddy module information.
func (h *HTTPHandler) CaddyModule() caddy.ModuleInfo {
	lp, id := h.lp, h.moduleID
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID(id),
		New: func() caddy.Module { return newHTTPHandler(lp, id) },
	}
}

// Provision implements caddy.Provisioner. Uses an instance pool for
// concurrent request handling.
func (h *HTTPHandler) Provision(ctx caddy.Context) error {
	return h.provisionPooled(ctx, true)
}

// Validate implements caddy.Validator.
func (h *HTTPHandler) Validate() error { return h.validateInstance() }

// Cleanup implements caddy.CleanerUpper.
func (h *HTTPHandler) Cleanup() error { return h.cleanupInstance() }

// ServeHTTP implements caddyhttp.MiddlewareHandler by forwarding the
// request to the guest's http-handler.serve export via the instance pool.
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.pool == nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("module %s: wasm instance pool not provisioned", h.moduleID))
	}

	inst, err := h.pool.Get(r.Context())
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	defer h.pool.Put(inst)

	// Wire request-scoped replacer and vars from the live request context.
	repl, _ := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	scope := &runtime.HTTPScope{
		W: w,
		R: r,
		Next: func(w http.ResponseWriter, r *http.Request) error {
			return next.ServeHTTP(w, r)
		},
		Replace: func(input, empty string) string {
			if repl != nil {
				return repl.ReplaceAll(input, empty)
			}
			return input
		},
		GetVar: func(key string) (any, bool) {
			v := caddyhttp.GetVar(r.Context(), key)
			return v, v != nil
		},
		SetVar: func(key string, value any) {
			caddyhttp.SetVar(r.Context(), key, value)
		},
	}

	err = inst.ServeHTTP(r.Context(), scope)

	// A guest error carrying an HTTP status hint maps to caddyhttp.Error
	// so Caddy's error routes see the intended status code.
	var pe *runtime.PluginError
	if errors.As(err, &pe) && pe.Status != 0 {
		return caddyhttp.Error(pe.Status, pe)
	}
	return err
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler by handing the
// directive's tokens to the guest's config.unmarshal-caddyfile export.
func (h *HTTPHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return h.unmarshalCaddyfile(d)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*HTTPHandler)(nil)
	_ caddy.Validator             = (*HTTPHandler)(nil)
	_ caddy.CleanerUpper          = (*HTTPHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*HTTPHandler)(nil)
	_ caddyfile.Unmarshaler       = (*HTTPHandler)(nil)
)
