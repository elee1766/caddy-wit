package shim

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/elee1766/caddy-wit/pkg/runtime"
)

// UpstreamSource adapts a wasm plugin module in the
// http.reverse_proxy.upstreams.* namespace to reverseproxy.UpstreamSource.
type UpstreamSource struct {
	shimCore
}

func newUpstreamSource(lp *LoadedPlugin, moduleID string) *UpstreamSource {
	return &UpstreamSource{shimCore{lp: lp, moduleID: moduleID}}
}

// CaddyModule returns the Caddy module information.
func (u *UpstreamSource) CaddyModule() caddy.ModuleInfo {
	lp, id := u.lp, u.moduleID
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID(id),
		New: func() caddy.Module { return newUpstreamSource(lp, id) },
	}
}

// Provision implements caddy.Provisioner. Uses an instance pool for
// concurrent request handling (GetUpstreams is called per-request).
func (u *UpstreamSource) Provision(ctx caddy.Context) error {
	return u.provisionPooled(ctx, true)
}

// Validate implements caddy.Validator.
func (u *UpstreamSource) Validate() error { return u.validateInstance() }

// Cleanup implements caddy.CleanerUpper.
func (u *UpstreamSource) Cleanup() error { return u.cleanupInstance() }

// GetUpstreams implements reverseproxy.UpstreamSource by calling the guest's
// upstream-source.get-upstreams export via the instance pool.
func (u *UpstreamSource) GetUpstreams(r *http.Request) ([]*reverseproxy.Upstream, error) {
	if u.pool == nil {
		return nil, fmt.Errorf("module %s: wasm instance pool not provisioned", u.moduleID)
	}

	inst, err := u.pool.Get(r.Context())
	if err != nil {
		return nil, err
	}
	defer u.pool.Put(inst)

	scope := &runtime.HTTPScope{
		W: nopResponseWriter{},
		R: r,
		// Next is nil for upstream-source calls.
	}

	ups, err := inst.GetUpstreams(r.Context(), scope)
	if err != nil {
		return nil, err
	}

	out := make([]*reverseproxy.Upstream, 0, len(ups))
	for _, u := range ups {
		out = append(out, &reverseproxy.Upstream{
			Dial:        u.Dial,
			MaxRequests: u.MaxRequests,
		})
	}
	return out, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler by handing the
// directive's tokens to the guest's config.unmarshal-caddyfile export.
func (u *UpstreamSource) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return u.unmarshalCaddyfile(d)
}

// Interface guards
var (
	_ caddy.Provisioner             = (*UpstreamSource)(nil)
	_ caddy.Validator               = (*UpstreamSource)(nil)
	_ caddy.CleanerUpper            = (*UpstreamSource)(nil)
	_ reverseproxy.UpstreamSource   = (*UpstreamSource)(nil)
	_ caddyfile.Unmarshaler         = (*UpstreamSource)(nil)
)
