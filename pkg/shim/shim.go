// Package shim adapts wasm plugin modules (hosted by the runtime package)
// to Caddy's native extension interfaces.
//
// For every Caddy module a wasm plugin declares (see runtime.ModuleDecl),
// Register creates a dynamic Caddy module whose New func constructs a
// namespace-appropriate shim value: an HTTP handler, HTTP matcher,
// filesystem, TLS issuer, TLS certificate loader, storage backend, or event
// handler. The shim carries the plugin's raw JSON config verbatim across
// the host/guest boundary and forwards each Caddy interface call to the
// corresponding guest export.
//
// Concurrency: HTTP handlers and matchers use a runtime.Pool to serve
// concurrent requests. Non-HTTP shims (fs, tls, storage, events, dns) use
// a single instance — they're not on the hot path and their callers don't
// hit them concurrently per module.
package shim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	goruntime "runtime"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/elee1766/caddy-wit/pkg/runtime"
	"go.uber.org/zap"
)

// bootTimeout bounds out-of-band guest calls that don't have a natural
// caller-supplied context (Caddyfile unmarshaling, cleanup, certificate
// loading, ...).
const bootTimeout = 30 * time.Second

// bootCtx returns a background context for out-of-band guest calls.
func bootCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), bootTimeout)
}

// shimCore is embedded in every shim type. It holds the identity of the
// wasm-backed module (which plugin, which module ID), the raw JSON config,
// and — after Provision — the live wasm module instance.
//
// Config handling: Caddy module configs must round-trip arbitrary JSON that
// only the guest understands, so shimCore implements json.Marshaler and
// json.Unmarshaler (promoted to the outer shim types) that capture and
// re-emit the whole config object verbatim. The plugin pointer and module
// ID are injected by the ModuleInfo.New closure, never from JSON.
type shimCore struct {
	// Raw is the module's entire JSON configuration, opaque to the host.
	Raw json.RawMessage

	lp       *LoadedPlugin
	moduleID string

	// Single-instance path (non-HTTP shims: fs, tls, storage, events, dns).
	mod    *runtime.Module
	inst   *runtime.Instance
	logger *zap.Logger

	// Pool path (HTTP handlers and matchers for concurrent request serving).
	pool *runtime.Pool
}

// UnmarshalJSON stores the whole config object verbatim.
func (c *shimCore) UnmarshalJSON(b []byte) error {
	c.Raw = append(c.Raw[:0:0], b...)
	return nil
}

// MarshalJSON emits the stored config object back. It always emits a JSON
// object (never null) because Caddy's config serializer injects the inline
// module-name key into it.
func (c *shimCore) MarshalJSON() ([]byte, error) {
	if len(c.Raw) == 0 {
		return []byte("{}"), nil
	}
	return c.Raw, nil
}

// defaultPoolMax is the default maximum pool size for HTTP handlers/matchers.
// Chosen as GOMAXPROCS*4 — enough to saturate typical request concurrency
// without unbounded growth. Each slot is ~1-5 MB of wasm linear memory.
// TODO: make configurable via pool_size Caddyfile subdirective / JSON field.
func defaultPoolMax() int {
	n := goruntime.GOMAXPROCS(0) * 4
	if n < 8 {
		n = 8
	}
	return n
}

// provisionPooled creates a runtime.Pool for concurrent request handling.
// Used by HTTP handlers and matchers.
func (c *shimCore) provisionPooled(ctx caddy.Context, withEvents bool) error {
	if c.lp == nil || c.lp.Plugin == nil {
		return fmt.Errorf("module %s: shim constructed without a plugin (must be created via its registered ModuleInfo.New)", c.moduleID)
	}

	logger := ctx.Logger()
	repl := caddy.NewReplacer()

	env := &runtime.Env{
		Logger:      logger,
		Storage:     ctx.Storage(),
		Replace:     repl.ReplaceAll,
		GetVar:      repl.GetString,
		Permissions: c.lp.Permissions,
		KV:          runtime.NewKVStore(),
		SharedKV:    globalSharedKV,
	}
	if withEvents {
		env.EmitEvent = makeEmitEvent(ctx)
	}

	raw := c.Raw
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}

	pool, err := runtime.NewPool(ctx, c.lp.Plugin, env, c.moduleID, string(raw), runtime.PoolConfig{
		MinInstances: 2,
		MaxInstances: defaultPoolMax(),
	})
	if err != nil {
		return fmt.Errorf("module %s: creating instance pool for plugin %q: %w", c.moduleID, c.lp.Name, err)
	}

	c.pool = pool
	c.logger = logger
	return nil
}

// provisionInstance is the common provisioning path: it builds the host
// Env from the caddy.Context, instantiates a fresh wasm module for this
// Caddy module instance, and provisions the guest with the raw JSON config.
//
// Used by non-HTTP shims (fs, tls, storage, events, dns) that don't need
// concurrent request handling — their callers don't hit them concurrently
// per module instance.
//
// withEvents controls whether the guest gets an emit-event host import;
// it must be false for modules provisioned by the events app itself
// (events.handlers.*) and for storage modules that are provisioned before
// apps exist, since ctx.App("events") would recurse or force premature
// app loading.
func (c *shimCore) provisionInstance(ctx caddy.Context, withEvents bool) error {
	if c.lp == nil || c.lp.Plugin == nil {
		return fmt.Errorf("module %s: shim constructed without a plugin (must be created via its registered ModuleInfo.New)", c.moduleID)
	}

	logger := ctx.Logger()

	// The replacer here is the global (config-time) replacer. Request-scoped
	// placeholders would need the replacer from r.Context() via
	// caddy.ReplacerCtxKey; see the TODO in HTTPHandler.ServeHTTP.
	repl := caddy.NewReplacer()

	env := &runtime.Env{
		Logger:  logger,
		Storage: ctx.Storage(),
		Replace: repl.ReplaceAll,
		GetVar:  repl.GetString,
		// Network access is opt-in per plugin: only the permissions the
		// manifest entry granted (see loader/manifest.Plugin.Permissions)
		// are passed through; the zero value disables host-http/host-tcp.
		Permissions: c.lp.Permissions,
		KV:          runtime.NewKVStore(),
		SharedKV:    globalSharedKV,
	}
	if withEvents {
		env.EmitEvent = makeEmitEvent(ctx)
	}

	mod, err := c.lp.Plugin.Instantiate(ctx, env)
	if err != nil {
		return fmt.Errorf("module %s: instantiating wasm plugin %q: %w", c.moduleID, c.lp.Name, err)
	}

	raw := c.Raw
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	inst, err := mod.Provision(ctx, c.moduleID, string(raw))
	if err != nil {
		// best-effort teardown of the half-provisioned instance
		cctx, cancel := bootCtx()
		defer cancel()
		_ = mod.Close(cctx)
		return fmt.Errorf("module %s: provisioning guest instance: %w", c.moduleID, err)
	}

	c.mod = mod
	c.inst = inst
	c.logger = logger
	return nil
}

// validateInstance calls the guest's lifecycle validate.
func (c *shimCore) validateInstance() error {
	if c.pool != nil {
		// Pooled: get a slot, validate, return it.
		ctx, cancel := bootCtx()
		defer cancel()
		inst, err := c.pool.Get(ctx)
		if err != nil {
			return fmt.Errorf("module %s: pool get for validate: %w", c.moduleID, err)
		}
		defer c.pool.Put(inst)
		return inst.Validate(ctx)
	}
	if c.inst == nil {
		return fmt.Errorf("module %s: not provisioned", c.moduleID)
	}
	ctx, cancel := bootCtx()
	defer cancel()
	return c.inst.Validate(ctx)
}

// cleanupInstance tears down the guest instance and its wasm module,
// or drains the pool if one is set.
func (c *shimCore) cleanupInstance() error {
	ctx, cancel := bootCtx()
	defer cancel()
	var errs []error
	if c.pool != nil {
		errs = append(errs, c.pool.Close(ctx))
		c.pool = nil
	}
	if c.inst != nil {
		errs = append(errs, c.inst.Cleanup(ctx))
		c.inst = nil
	}
	if c.mod != nil {
		errs = append(errs, c.mod.Close(ctx))
		c.mod = nil
	}
	return errors.Join(errs...)
}

// Note: KVStore cleanup happens implicitly — the KVStore is referenced
// only via the Env, which becomes unreachable once the pool/module are
// closed. The GC reclaims it. If explicit cleanup is desired (e.g. to
// release memory eagerly on a hot-reload), callers can call env.KV.Close()
// before closing the module/pool.

// unmarshalCaddyfile implements the shared caddyfile.Unmarshaler flow:
// collect every token in the directive's segment (including the directive
// name itself), hand them to a scratch guest instance's
// config.unmarshal-caddyfile export, and stash the resulting JSON config
// into Raw for later provisioning.
func (c *shimCore) unmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if c.lp == nil || c.lp.Plugin == nil {
		return fmt.Errorf("module %s: shim constructed without a plugin", c.moduleID)
	}
	if !c.lp.Caps[runtime.CapConfig] {
		return fmt.Errorf("module %s: plugin %q does not support Caddyfile config (missing %q capability)", c.moduleID, c.lp.Name, runtime.CapConfig)
	}

	var toks []runtime.Token
	for d.Next() {
		t := d.Token()
		line := t.Line
		if line < 0 {
			line = 0
		}
		toks = append(toks, runtime.Token{
			File:   t.File,
			Line:   uint32(line),
			Text:   t.Text,
			Quoted: t.Quoted(),
		})
	}

	ctx, cancel := bootCtx()
	defer cancel()

	// Scratch instance with a minimal Env: unmarshaling happens at config
	// adapt time, before any caddy.Context exists.
	mod, err := c.lp.Plugin.Instantiate(ctx, &runtime.Env{Logger: zap.NewNop()})
	if err != nil {
		return fmt.Errorf("module %s: instantiating scratch wasm instance: %w", c.moduleID, err)
	}
	defer func() { _ = mod.Close(ctx) }()

	out, err := mod.UnmarshalCaddyfile(ctx, c.moduleID, toks)
	if err != nil {
		return fmt.Errorf("module %s: guest unmarshal-caddyfile: %w", c.moduleID, err)
	}
	if !json.Valid([]byte(out)) {
		return fmt.Errorf("module %s: guest unmarshal-caddyfile returned invalid JSON", c.moduleID)
	}
	c.Raw = json.RawMessage(out)
	return nil
}

// makeEmitEvent wires Env.EmitEvent to the caddyevents app, if available.
// Returns nil (host import disabled) when the events app cannot be loaded.
//
// Signature verified against caddy v2.11.4:
//
//	func (app *caddyevents.App) Emit(ctx caddy.Context, eventName string, data map[string]any) caddy.Event
func makeEmitEvent(ctx caddy.Context) func(context.Context, string, string) error {
	appIface, err := ctx.App("events")
	if err != nil {
		return nil
	}
	app, ok := appIface.(*caddyevents.App)
	if !ok {
		return nil
	}
	base := ctx
	return func(callCtx context.Context, name, dataJSON string) error {
		var data map[string]any
		if dataJSON != "" && dataJSON != "null" {
			if err := json.Unmarshal([]byte(dataJSON), &data); err != nil {
				return fmt.Errorf("event data must be a JSON object: %w", err)
			}
		}
		// caddy.Context embeds context.Context; substitute the caller's
		// context so cancellation/replacer values propagate into Emit.
		ectx := base
		if callCtx != nil {
			ectx.Context = callCtx
		}
		e := app.Emit(ectx, name, data)
		return e.Aborted
	}
}
