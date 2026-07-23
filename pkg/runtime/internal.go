package runtime

// internal.go holds the internal state structs behind Runtime, Plugin and
// Module, plus runtime construction, plugin compilation/capability
// detection, and module instantiation.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/tetratelabs/wazero"
	wazeroapi "github.com/tetratelabs/wazero/api"
	wasi "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/elee1766/caddy-wit/pkg/abi"
	"github.com/elee1766/caddy-wit/pkg/runtime/gen"
)

var (
	errModuleClosed   = errors.New("caddywit: module is closed")
	errInstanceClosed = errors.New("caddywit: instance already cleaned up")
	errFileClosed     = errors.New("caddywit: file is closed")
	errNilScope       = errors.New("caddywit: nil http scope")
)

// Guest resource handles for the per-call host-owned http-types resources.
// serveHTTP/matches mint exactly one request (and one response-writer) per
// call, so fixed handles are sufficient; they resolve to the *HTTPScope
// carried on the context (see withScope).
const (
	requestHandle        uint32 = 1
	responseWriterHandle uint32 = 2
)

type runtimeInternal struct {
	rt wazero.Runtime
}

type pluginInternal struct {
	parent   *Runtime
	compiled wazero.CompiledModule
	caps     map[Capability]bool
}

type moduleInternal struct {
	// mu serializes every call into the (single-threaded) wasm instance,
	// including re-entrant host calls' access to mutable state.
	mu      sync.Mutex
	mod     wazeroapi.Module
	exports *gen.Exports
	tables  *abi.ResourceTables
	env     *Env

	// tcpMu guards the host-tcp connection table. It is separate from mu
	// because host-tcp calls arrive re-entrantly while mu is held by the
	// in-flight guest call.
	tcpMu    sync.Mutex
	tcpConns map[uint32]net.Conn
	tcpNext  uint32
}

// storeConn registers a host-tcp connection and mints its handle
// (host-minted handles start at 1).
func (m *Module) storeConn(c net.Conn) uint32 {
	m.internal.tcpMu.Lock()
	defer m.internal.tcpMu.Unlock()
	if m.internal.tcpConns == nil {
		m.internal.tcpConns = make(map[uint32]net.Conn)
	}
	m.internal.tcpNext++
	handle := m.internal.tcpNext
	m.internal.tcpConns[handle] = c
	return handle
}

// conn resolves a host-tcp connection handle, or nil.
func (m *Module) conn(handle uint32) net.Conn {
	m.internal.tcpMu.Lock()
	defer m.internal.tcpMu.Unlock()
	return m.internal.tcpConns[handle]
}

// removeConn removes and returns a host-tcp connection, or nil if the
// handle is unknown (already closed/dropped).
func (m *Module) removeConn(handle uint32) net.Conn {
	m.internal.tcpMu.Lock()
	defer m.internal.tcpMu.Unlock()
	c := m.internal.tcpConns[handle]
	delete(m.internal.tcpConns, handle)
	return c
}

// closeAllConns closes every live host-tcp connection (module teardown).
func (m *Module) closeAllConns() {
	m.internal.tcpMu.Lock()
	conns := m.internal.tcpConns
	m.internal.tcpConns = nil
	m.internal.tcpMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func newRuntime(ctx context.Context) (*Runtime, error) {
	rt := wazero.NewRuntime(ctx)
	if _, err := wasi.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("caddywit: instantiating WASI: %w", err)
	}
	// gen.Instantiate must run exactly once per wazero runtime; each
	// Runtime owns a fresh wazero runtime, so calling it here is the guard.
	if err := gen.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("caddywit: instantiating caddy:plugin host modules: %w", err)
	}
	return &Runtime{internal: runtimeInternal{rt: rt}}, nil
}

func (r *Runtime) close(ctx context.Context) error {
	if r == nil || r.internal.rt == nil {
		return nil
	}
	return r.internal.rt.Close(ctx)
}

// capabilityPrefixes maps each Capability to the export-name prefix of its
// interface's guest exports ("caddy:plugin/<iface>@0.1.0#").
var capabilityPrefixes = map[Capability]string{
	CapManifest:      gen.ExportPrefixManifest,
	CapLifecycle:     gen.ExportPrefixLifecycle,
	CapConfig:        gen.ExportPrefixConfig,
	CapHTTPHandler:   gen.ExportPrefixHTTPHandler,
	CapHTTPMatcher:   gen.ExportPrefixHTTPMatcher,
	CapFS:            gen.ExportPrefixFS,
	CapTLSIssuer:     gen.ExportPrefixTLSIssuer,
	CapTLSCertLoader: gen.ExportPrefixTLSCertLoader,
	CapStorage:       gen.ExportPrefixStorageProvider,
	CapEventHandler:  gen.ExportPrefixEventHandler,
	CapDNSProvider:      gen.ExportPrefixDNSProvider,
	CapUpstreamSource:   gen.ExportPrefixUpstreamSource,
}

func (r *Runtime) compilePlugin(ctx context.Context, wasm []byte) (*Plugin, error) {
	if r == nil || r.internal.rt == nil {
		return nil, errors.New("caddywit: runtime is closed")
	}
	compiled, err := r.internal.rt.CompileModule(ctx, wasm)
	if err != nil {
		return nil, fmt.Errorf("caddywit: compiling plugin: %w", err)
	}
	caps := make(map[Capability]bool)
	for name := range compiled.ExportedFunctions() {
		for c, prefix := range capabilityPrefixes {
			if strings.HasPrefix(name, prefix) {
				caps[c] = true
			}
		}
	}
	return &Plugin{internal: pluginInternal{
		parent:   r,
		compiled: compiled,
		caps:     caps,
	}}, nil
}

func (p *Plugin) capabilities() map[Capability]bool { return p.internal.caps }

func (p *Plugin) info(ctx context.Context) (PluginInfo, error) {
	// Scratch instance with an empty environment, used only for describe.
	mod, err := p.instantiate(ctx, &Env{})
	if err != nil {
		return PluginInfo{}, err
	}
	defer func() { _ = mod.Close(ctx) }()
	return mod.describe(ctx)
}

func (p *Plugin) instantiate(ctx context.Context, env *Env) (*Module, error) {
	if p == nil || p.internal.compiled == nil || p.internal.parent == nil {
		return nil, errors.New("caddywit: plugin not compiled")
	}
	if env == nil {
		env = &Env{}
	}

	// WithName("") makes the module anonymous so the same CompiledModule
	// can be instantiated many times in one runtime. WithStartFunctions()
	// clears wazero's default of running "_start" during instantiation:
	// wit-bindgen guests are wasip1 *reactor* modules, which export
	// "_initialize" instead ("_start" is for command modules and typically
	// exits the instance). We invoke "_initialize" manually below so that
	// it runs with a fully wired call context — guest init code may already
	// call host imports, which need the host + resource tables on ctx.
	cfg := wazero.NewModuleConfig().WithName("").WithStartFunctions()
	mod, err := p.internal.parent.internal.rt.InstantiateModule(ctx, p.internal.compiled, cfg)
	if err != nil {
		return nil, fmt.Errorf("caddywit: instantiating plugin: %w", err)
	}

	m := &Module{internal: moduleInternal{
		mod:     mod,
		exports: gen.NewExports(mod),
		tables:  abi.NewResourceTables(),
		env:     env,
	}}

	if init := mod.ExportedFunction("_initialize"); init != nil {
		if _, err := init.Call(m.callCtx(ctx)); err != nil {
			_ = mod.Close(ctx)
			return nil, fmt.Errorf("caddywit: running _initialize: %w", err)
		}
	}
	return m, nil
}

func (m *Module) close(ctx context.Context) error {
	m.internal.mu.Lock()
	defer m.internal.mu.Unlock()
	m.closeAllConns()
	if m.internal.mod == nil {
		return nil
	}
	err := m.internal.mod.Close(ctx)
	m.internal.mod = nil
	m.internal.exports = nil
	return err
}

// callCtx prepares a context for a guest call (or for "_initialize"): it
// attaches the host implementation bound to this Module's Env and the
// module's canonical-ABI resource tables. Every entry into guest code must
// go through this.
func (m *Module) callCtx(ctx context.Context) context.Context {
	ctx = gen.WithHost(ctx, hostImpl{m: m})
	ctx = abi.WithTables(ctx, m.internal.tables)
	return ctx
}

// env never returns nil.
func (m *Module) env() *Env {
	if m != nil && m.internal.env != nil {
		return m.internal.env
	}
	return &Env{}
}

// scopeCtxKey is the runtime-private context key carrying the *scopeState
// that the fixed request/response-writer handles (and any minted
// buffered-response handles) resolve to during a single serveHTTP/matches
// call.
type scopeCtxKey struct{}

// scopeState wraps the public *HTTPScope with runtime-private per-call
// state: the buffered-response table minted by next-buffered. It is only
// touched by re-entrant host calls of the single in-flight guest call, so
// it needs no locking.
type scopeState struct {
	scope *HTTPScope

	// buffered holds the buffered-response resources minted by
	// next-buffered during this call; handles start at 1.
	buffered     map[uint32]*bufferedResponse
	bufferedNext uint32
}

// mintBuffered stores br and returns its handle.
func (st *scopeState) mintBuffered(br *bufferedResponse) uint32 {
	if st.buffered == nil {
		st.buffered = make(map[uint32]*bufferedResponse)
	}
	st.bufferedNext++
	st.buffered[st.bufferedNext] = br
	return st.bufferedNext
}

func withScope(ctx context.Context, s *HTTPScope) context.Context {
	return context.WithValue(ctx, scopeCtxKey{}, &scopeState{scope: s})
}

func scopeStateFrom(ctx context.Context) *scopeState {
	st, _ := ctx.Value(scopeCtxKey{}).(*scopeState)
	return st
}

func scopeFrom(ctx context.Context) *HTTPScope {
	if st := scopeStateFrom(ctx); st != nil {
		return st.scope
	}
	return nil
}
