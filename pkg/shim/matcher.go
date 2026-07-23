package shim

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/elee1766/caddy-wit/pkg/runtime"
)

// HTTPMatcher adapts a wasm plugin module in the http.matchers.* namespace
// to caddyhttp.RequestMatcherWithError.
type HTTPMatcher struct {
	shimCore
}

func newHTTPMatcher(lp *LoadedPlugin, moduleID string) *HTTPMatcher {
	return &HTTPMatcher{shimCore{lp: lp, moduleID: moduleID}}
}

// CaddyModule returns the Caddy module information.
func (m *HTTPMatcher) CaddyModule() caddy.ModuleInfo {
	lp, id := m.lp, m.moduleID
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID(id),
		New: func() caddy.Module { return newHTTPMatcher(lp, id) },
	}
}

// Provision implements caddy.Provisioner. Uses an instance pool for
// concurrent request matching.
func (m *HTTPMatcher) Provision(ctx caddy.Context) error {
	return m.provisionPooled(ctx, true)
}

// Validate implements caddy.Validator.
func (m *HTTPMatcher) Validate() error { return m.validateInstance() }

// Cleanup implements caddy.CleanerUpper.
func (m *HTTPMatcher) Cleanup() error { return m.cleanupInstance() }

// MatchWithError implements caddyhttp.RequestMatcherWithError by calling
// the guest's http-matcher.matches export via the instance pool.
func (m *HTTPMatcher) MatchWithError(r *http.Request) (bool, error) {
	if m.pool == nil {
		return false, fmt.Errorf("module %s: wasm instance pool not provisioned", m.moduleID)
	}

	inst, err := m.pool.Get(r.Context())
	if err != nil {
		return false, err
	}
	defer m.pool.Put(inst)

	// Matcher calls have no response writer; pass a no-op writer instead of
	// nil so a misbehaving guest that touches the response-writer resource
	// cannot cause a nil dereference in the runtime.
	scope := &runtime.HTTPScope{
		W: nopResponseWriter{},
		R: r,
		// Next is nil for matcher calls; see runtime.HTTPScope docs.
	}
	return inst.Matches(r.Context(), scope)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler by handing the
// matcher's tokens to the guest's config.unmarshal-caddyfile export.
func (m *HTTPMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return m.unmarshalCaddyfile(d)
}

// nopResponseWriter discards everything written to it.
type nopResponseWriter struct{}

func (nopResponseWriter) Header() http.Header         { return http.Header{} }
func (nopResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (nopResponseWriter) WriteHeader(int)             {}

// Interface guards
var (
	_ caddy.Provisioner                 = (*HTTPMatcher)(nil)
	_ caddy.Validator                   = (*HTTPMatcher)(nil)
	_ caddy.CleanerUpper                = (*HTTPMatcher)(nil)
	_ caddyhttp.RequestMatcherWithError = (*HTTPMatcher)(nil)
	_ caddyfile.Unmarshaler             = (*HTTPMatcher)(nil)
	_ http.ResponseWriter               = nopResponseWriter{}
)
