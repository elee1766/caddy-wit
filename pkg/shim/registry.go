package shim

import (
	"fmt"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/elee1766/caddy-wit/pkg/runtime"
)

// LoadedPlugin is a compiled wasm plugin together with the metadata the
// shims need to construct instances of its declared Caddy modules.
type LoadedPlugin struct {
	// Name is the plugin's self-reported name (manifest.plugin-info.name).
	Name string
	// Plugin is the compiled (not instantiated) wasm binary.
	Plugin *runtime.Plugin
	// Caps reports which extension-point interfaces the binary exports.
	Caps map[runtime.Capability]bool
	// Permissions are the network capabilities granted to this plugin by
	// its manifest entry (see loader/manifest.Plugin.Permissions). They
	// gate the caddy:plugin/host-http and host-tcp imports; the zero
	// value grants no network access.
	Permissions runtime.Permissions
}

// supportedNamespaces maps Caddy module namespace prefixes to the guest
// capability each requires. Order matters only for the error message.
var supportedNamespaces = []struct {
	prefix string
	cap    runtime.Capability
}{
	{"http.handlers.", runtime.CapHTTPHandler},
	{"http.matchers.", runtime.CapHTTPMatcher},
	{"caddy.fs.", runtime.CapFS},
	{"tls.issuance.", runtime.CapTLSIssuer},
	{"tls.certificates.", runtime.CapTLSCertLoader},
	{"caddy.storage.", runtime.CapStorage},
	{"events.handlers.", runtime.CapEventHandler},
	{"dns.providers.", runtime.CapDNSProvider},
	{"http.reverse_proxy.upstreams.", runtime.CapUpstreamSource},
}

// Register registers one Caddy module declared by a wasm plugin. The module
// ID's namespace prefix selects the shim type; the plugin must export the
// matching capability. For http.handlers modules whose plugin also exports
// the config capability, a Caddyfile handler directive named after the
// module's last ID segment is registered as well.
func Register(lp *LoadedPlugin, decl runtime.ModuleDecl) error {
	if lp == nil || lp.Plugin == nil {
		return fmt.Errorf("nil plugin")
	}
	id := decl.ID
	name := lastSegment(id)
	if name == "" {
		return fmt.Errorf("plugin %q: invalid module ID %q", lp.Name, id)
	}

	var (
		needCap runtime.Capability
		proto   caddy.Module
	)
	switch {
	case strings.HasPrefix(id, "http.handlers."):
		needCap, proto = runtime.CapHTTPHandler, newHTTPHandler(lp, id)
	case strings.HasPrefix(id, "http.matchers."):
		needCap, proto = runtime.CapHTTPMatcher, newHTTPMatcher(lp, id)
	case strings.HasPrefix(id, "caddy.fs."):
		needCap, proto = runtime.CapFS, newFS(lp, id)
	case strings.HasPrefix(id, "tls.issuance."):
		needCap, proto = runtime.CapTLSIssuer, newTLSIssuer(lp, id)
	case strings.HasPrefix(id, "tls.certificates."):
		needCap, proto = runtime.CapTLSCertLoader, newTLSCertLoader(lp, id)
	case strings.HasPrefix(id, "caddy.storage."):
		needCap, proto = runtime.CapStorage, newStorage(lp, id)
	case strings.HasPrefix(id, "events.handlers."):
		needCap, proto = runtime.CapEventHandler, newEventHandler(lp, id)
	case strings.HasPrefix(id, "dns.providers."):
		// The last ID label is the provider name Caddy config refers to
		// (e.g. dns.providers.cloudflare -> "cloudflare").
		needCap, proto = runtime.CapDNSProvider, newDNSProvider(lp, id)
	case strings.HasPrefix(id, "http.reverse_proxy.upstreams."):
		needCap, proto = runtime.CapUpstreamSource, newUpstreamSource(lp, id)
	default:
		return fmt.Errorf("plugin %q: module %q: unsupported namespace; supported namespaces: %s",
			lp.Name, id, supportedNamespaceList())
	}

	if !lp.Caps[needCap] {
		return fmt.Errorf("plugin %q: module %q requires capability %q, but the plugin does not export it",
			lp.Name, id, needCap)
	}

	if err := safeRegisterModule(proto); err != nil {
		return fmt.Errorf("plugin %q: module %q: %w", lp.Name, id, err)
	}

	// If the plugin can unmarshal Caddyfile tokens, expose http.handlers
	// modules as first-class Caddyfile directives.
	if needCap == runtime.CapHTTPHandler && lp.Caps[runtime.CapConfig] {
		registerHandlerDirective(lp, id, name, decl.CaddyfileOrder)
	}
	return nil
}

func supportedNamespaceList() string {
	parts := make([]string, len(supportedNamespaces))
	for i, ns := range supportedNamespaces {
		parts[i] = ns.prefix + "*"
	}
	return strings.Join(parts, ", ")
}

// lastSegment returns the final dot-separated label of a module ID
// (the module name), or "" if the ID is malformed.
func lastSegment(id string) string {
	if i := strings.LastIndexByte(id, '.'); i >= 0 {
		return id[i+1:]
	}
	return id
}

// safeRegisterModule calls caddy.RegisterModule, converting its panics
// (duplicate ID, reserved ID, ...) into errors so one bad plugin cannot
// take down the whole load.
func safeRegisterModule(m caddy.Module) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("registering caddy module: %v", r)
		}
	}()
	caddy.RegisterModule(m)
	return nil
}

// registerHandlerDirective registers a Caddyfile directive for an
// http.handlers module. The parse func delegates token unmarshaling to the
// guest (see shimCore.unmarshalCaddyfile) and returns a handler shim
// carrying the resulting JSON config. order, if non-nil, is the ordering
// the plugin declared in manifest.describe.
func registerHandlerDirective(lp *LoadedPlugin, moduleID, dir string, order *runtime.DirectiveOrder) {
	// RegisterHandlerDirective panics if the directive name is already
	// taken (by the standard distribution or another plugin). Recover so a
	// name collision degrades to "no Caddyfile sugar" instead of crashing;
	// the module remains usable via JSON config.
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "caddy-wit: not registering Caddyfile directive %q for %s: %v\n", dir, moduleID, r)
			}
		}()
		httpcaddyfile.RegisterHandlerDirective(dir, func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
			hh := newHTTPHandler(lp, moduleID)
			if err := hh.UnmarshalCaddyfile(h.Dispenser); err != nil {
				return nil, err
			}
			return hh, nil
		})
	}()

	// Order the directive, mirroring what a native plugin would do in its
	// init() via httpcaddyfile.RegisterDirectiveOrder: the manifest's
	// caddyfile-order declares a position (before/after) relative to a
	// STANDARD-distribution directive; absent means the host default
	// (before file_server). Users can still override with the `order`
	// global option. RegisterDirectiveOrder panics on already-ordered
	// directives (e.g. two plugins declaring the same directive name, or a
	// re-registration), on positions other than before/after, and on
	// reference directives not in the standard distribution — so wrap in
	// recover: a bad declaration logs and degrades (falling back to the
	// default order when possible) instead of crashing Caddy.
	position, relativeTo := httpcaddyfile.Before, "file_server"
	if order != nil {
		position, relativeTo = httpcaddyfile.Positional(order.Position), order.RelativeTo
	}
	registered := func() (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "caddy-wit: not ordering Caddyfile directive %q (%s %s) for %s: %v\n",
					dir, position, relativeTo, moduleID, r)
			}
		}()
		httpcaddyfile.RegisterDirectiveOrder(dir, position, relativeTo)
		return true
	}()

	// A rejected declared order (bad position or non-standard reference
	// directive) falls back to the host default so the directive stays
	// usable without an `order` global.
	if !registered && order != nil {
		func() {
			defer func() { _ = recover() }()
			httpcaddyfile.RegisterDirectiveOrder(dir, httpcaddyfile.Before, "file_server")
		}()
	}
}
