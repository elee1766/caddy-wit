// Package runtime hosts caddy:plugin wasm guests on wazero.
//
// Guests are core wasm modules produced by wit-bindgen against the
// caddy:plugin WIT package (the pre-componentize "canonical ABI core module"
// output). This package hand-implements the host side of the canonical ABI
// for the fixed set of interfaces in ../wit, which is what lets us stay on
// wazero (pure Go, no CGO) instead of requiring a component-model runtime.
//
// Concurrency: a wasm module instance is single-threaded. A Module
// serializes all calls with an internal mutex; callers that need request
// concurrency should maintain multiple Modules (pooling is planned, see
// TODOs in the loader).
package runtime

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// Capability identifies one of the guest-exported extension-point
// interfaces from the caddy:plugin WIT package.
type Capability string

const (
	CapManifest      Capability = "manifest"
	CapLifecycle     Capability = "lifecycle"
	CapConfig        Capability = "config"
	CapHTTPHandler   Capability = "http-handler"
	CapHTTPMatcher   Capability = "http-matcher"
	CapFS            Capability = "fs"
	CapTLSIssuer     Capability = "tls-issuer"
	CapTLSCertLoader Capability = "tls-cert-loader"
	CapStorage       Capability = "storage-provider"
	CapEventHandler  Capability = "event-handler"
	CapDNSProvider      Capability = "dns-provider"
	CapUpstreamSource   Capability = "upstream-source"
)

// DirectiveOrder mirrors caddy:plugin/manifest.caddyfile-order: where an
// http.handlers module's Caddyfile directive should be placed, relative to
// a directive from Caddy's standard distribution (the semantics of
// httpcaddyfile.RegisterDirectiveOrder).
type DirectiveOrder struct {
	// Position is "before" or "after".
	Position string
	// RelativeTo is a standard-distribution directive name, e.g. "respond".
	RelativeTo string
}

// ModuleDecl mirrors caddy:plugin/manifest.module-decl.
type ModuleDecl struct {
	// ID is the full Caddy module ID, e.g. "http.handlers.foo".
	ID   string
	Docs string
	// CaddyfileOrder is the declared Caddyfile directive ordering for
	// http.handlers modules; nil means the host default (before
	// file_server).
	CaddyfileOrder *DirectiveOrder
}

// PluginInfo mirrors caddy:plugin/manifest.plugin-info.
type PluginInfo struct {
	Name    string
	Version string
	Modules []ModuleDecl
}

// Token mirrors caddy:plugin/config.token. Quoted reports whether the
// token was enclosed in quotes in the Caddyfile (so a literal "{" argument
// can be distinguished from a block-opening brace).
type Token struct {
	File   string
	Line   uint32
	Text   string
	Quoted bool
}

// FileInfo mirrors caddy:plugin/fs.file-info.
type FileInfo struct {
	Name    string
	Size    uint64
	Mode    uint32
	ModTime time.Time
	Dir     bool
}

// IssuedCertificate mirrors caddy:plugin/tls-issuer.issued-certificate.
type IssuedCertificate struct {
	CertificatePEM []byte
	MetadataJSON   string // empty if none
}

// CertificateKeyPair mirrors caddy:plugin/tls-cert-loader.certificate-key-pair.
type CertificateKeyPair struct {
	CertificatePEM []byte
	KeyPEM         []byte
	Tags           []string
}

// KeyInfo mirrors caddy:plugin/types.key-info.
type KeyInfo struct {
	Key      string
	Modified time.Time
	Size     int64
	Terminal bool
}

// DNSRecord mirrors caddy:plugin/dns-provider.dns-record (libdns
// semantics: names relative to the zone).
type DNSRecord struct {
	// Type is the RR type, e.g. "TXT", "A", "CNAME".
	Type     string
	Name     string
	Value    string
	TTL      time.Duration
	Priority *uint16 // nil when the type has no priority
}

// Upstream mirrors caddy:plugin/upstream-source.upstream.
type Upstream struct {
	Dial        string
	MaxRequests int
}

// Event mirrors caddy:plugin/types.event.
type Event struct {
	ID        string
	Name      string
	Timestamp time.Time
	Origin    string
	DataJSON  string
}

// PluginError mirrors caddy:plugin/types.plugin-error. It satisfies error.
type PluginError struct {
	Message string
	// Status is an optional HTTP status hint; 0 means unset.
	Status int
}

func (e *PluginError) Error() string { return e.Message }

// ErrAborted is returned by Instance.HandleEvent when the guest aborts the
// event (caddy:plugin/event-handler.handler-error.aborted).
type abortedError struct{}

func (abortedError) Error() string { return "event aborted" }

// ErrEventAborted is the sentinel for guest-aborted events.
var ErrEventAborted error = abortedError{}

// Permissions gates the network host capabilities for one plugin. Both
// default to false: plugins get no network access unless their manifest
// entry grants it.
type Permissions struct {
	// HTTP enables the caddy:plugin/host-http outbound HTTP client.
	HTTP bool
	// TCP enables caddy:plugin/host-tcp raw TCP connections.
	TCP bool
}

// Env supplies the host capabilities (imports) available to a plugin module
// instance: logging, Caddy's configured storage, the global replacer, and
// event emission. Fields may be nil, in which case the corresponding host
// import fails gracefully (logs are dropped, storage/events return errors).
type Env struct {
	Logger    *zap.Logger
	Storage   certmagic.Storage
	Replace   func(input, empty string) string
	GetVar    func(key string) (string, bool)
	EmitEvent func(ctx context.Context, name string, dataJSON string) error

	// Permissions gates host-http/host-tcp. Zero value = no network.
	Permissions Permissions

	// KV is the per-plugin in-memory store (shared across pool slots,
	// isolated between plugins). Nil = host-kv calls return defaults.
	KV *KVStore

	// SharedKV is a global in-memory store shared across ALL plugins.
	// Wasm guests access it through host-kv with a "shared:" key prefix;
	// Go code accesses it directly. Nil = "shared:" keys return defaults.
	SharedKV *KVStore

	// HTTPClient serves caddy:plugin/host-http requests when
	// Permissions.HTTP is set. Nil uses a private default client with sane
	// timeouts. Response bodies are capped by the guest's request options
	// (default 16 MiB).
	HTTPClient *http.Client

	// DialTCP serves caddy:plugin/host-tcp connections when
	// Permissions.TCP is set. Nil uses a default net.Dialer.
	DialTCP func(ctx context.Context, address string, timeout time.Duration) (net.Conn, error)

}

// HTTPScope carries the live request/response pair (and the rest of the
// middleware chain) for the duration of a single ServeHTTP/Matches call.
// The guest's request/response-writer resource handles resolve to these.
type HTTPScope struct {
	W http.ResponseWriter
	R *http.Request
	// Next invokes the remainder of the middleware chain. May be nil for
	// matcher calls.
	Next func(w http.ResponseWriter, r *http.Request) error

	// Replace resolves placeholders against the request-scoped replacer
	// (e.g. {http.request.host}). Nil falls back to Env.Replace.
	Replace func(input, empty string) string

	// GetVar reads a request-scoped variable (caddyhttp vars). Nil falls
	// back to Env.GetVar.
	GetVar func(key string) (any, bool)

	// SetVar sets a request-scoped variable visible to downstream
	// handlers and other Caddy modules. Nil is a no-op.
	SetVar func(key string, value any)
}

// Runtime owns a wazero runtime pre-configured with the caddy:plugin host
// modules and WASI. One Runtime is shared by all loaded plugins.
type Runtime struct {
	internal runtimeInternal
}

// New creates a Runtime.
func New(ctx context.Context) (*Runtime, error) { return newRuntime(ctx) }

// Close releases all compiled code and instances.
func (r *Runtime) Close(ctx context.Context) error { return r.close(ctx) }

// CompilePlugin compiles a guest binary and inspects its exports to
// determine its capabilities. It does not instantiate the module.
func (r *Runtime) CompilePlugin(ctx context.Context, wasm []byte) (*Plugin, error) {
	return r.compilePlugin(ctx, wasm)
}

// Plugin is a compiled (not yet instantiated) plugin binary.
type Plugin struct {
	internal pluginInternal
}

// Capabilities reports which extension-point interfaces the binary exports.
func (p *Plugin) Capabilities() map[Capability]bool { return p.capabilities() }

// Info instantiates a scratch instance and calls manifest.describe.
func (p *Plugin) Info(ctx context.Context) (PluginInfo, error) { return p.info(ctx) }

// Instantiate creates a fresh module instance bound to env.
func (p *Plugin) Instantiate(ctx context.Context, env *Env) (*Module, error) {
	return p.instantiate(ctx, env)
}

// Module is a live, single-threaded wasm instance of a Plugin. All exported
// methods serialize on an internal mutex.
type Module struct {
	internal moduleInternal
}

// Close tears down the instance.
func (m *Module) Close(ctx context.Context) error { return m.close(ctx) }

// Describe calls caddy:plugin/manifest.describe.
func (m *Module) Describe(ctx context.Context) (PluginInfo, error) { return m.describe(ctx) }

// Provision calls caddy:plugin/lifecycle.instance.provision, returning a
// handle to the guest-side module instance.
func (m *Module) Provision(ctx context.Context, moduleID, configJSON string) (*Instance, error) {
	return m.provision(ctx, moduleID, configJSON)
}

// UnmarshalCaddyfile calls caddy:plugin/config.unmarshal-caddyfile and
// returns the resulting JSON config.
func (m *Module) UnmarshalCaddyfile(ctx context.Context, moduleID string, tokens []Token) (string, error) {
	return m.unmarshalCaddyfile(ctx, moduleID, tokens)
}

// Instance is a handle to a provisioned guest module instance
// (caddy:plugin/lifecycle.instance) plus typed wrappers for every
// extension-point call that takes one.
type Instance struct {
	m      *Module
	handle uint32
}

// Module returns the wasm instance this Instance lives in.
func (i *Instance) Module() *Module { return i.m }

// Validate calls lifecycle.instance.validate.
func (i *Instance) Validate(ctx context.Context) error { return i.validate(ctx) }

// Cleanup calls lifecycle.instance.cleanup and drops the guest handle.
func (i *Instance) Cleanup(ctx context.Context) error { return i.cleanup(ctx) }

// ServeHTTP calls http-handler.serve with scope resolving the request and
// response-writer resources. A guest error with a status hint is returned
// as *PluginError.
func (i *Instance) ServeHTTP(ctx context.Context, scope *HTTPScope) error {
	return i.serveHTTP(ctx, scope)
}

// Matches calls http-matcher.matches.
func (i *Instance) Matches(ctx context.Context, scope *HTTPScope) (bool, error) {
	return i.matches(ctx, scope)
}

// FSOpen calls fs.open and returns a handle to the guest-owned file.
func (i *Instance) FSOpen(ctx context.Context, path string) (*File, error) {
	return i.fsOpen(ctx, path)
}

// FSStat calls fs.stat.
func (i *Instance) FSStat(ctx context.Context, path string) (FileInfo, error) {
	return i.fsStat(ctx, path)
}

// FSReadDir calls fs.read-dir.
func (i *Instance) FSReadDir(ctx context.Context, path string) ([]FileInfo, error) {
	return i.fsReadDir(ctx, path)
}

// IssuerKey calls tls-issuer.issuer-key.
func (i *Instance) IssuerKey(ctx context.Context) (string, error) { return i.issuerKey(ctx) }

// Issue calls tls-issuer.issue.
func (i *Instance) Issue(ctx context.Context, csrDER []byte) (IssuedCertificate, error) {
	return i.issue(ctx, csrDER)
}

// LoadCertificates calls tls-cert-loader.load-certificates.
func (i *Instance) LoadCertificates(ctx context.Context) ([]CertificateKeyPair, error) {
	return i.loadCertificates(ctx)
}

// Storage* call the storage-provider interface (the guest acts as a
// certmagic.Storage backend).
func (i *Instance) StorageStore(ctx context.Context, key string, value []byte) error {
	return i.storageStore(ctx, key, value)
}
func (i *Instance) StorageLoad(ctx context.Context, key string) ([]byte, error) {
	return i.storageLoad(ctx, key)
}
func (i *Instance) StorageDelete(ctx context.Context, key string) error {
	return i.storageDelete(ctx, key)
}
func (i *Instance) StorageExists(ctx context.Context, key string) (bool, error) {
	return i.storageExists(ctx, key)
}
func (i *Instance) StorageList(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	return i.storageList(ctx, prefix, recursive)
}
func (i *Instance) StorageStat(ctx context.Context, key string) (KeyInfo, error) {
	return i.storageStat(ctx, key)
}
func (i *Instance) StorageLock(ctx context.Context, name string) error {
	return i.storageLock(ctx, name)
}
func (i *Instance) StorageUnlock(ctx context.Context, name string) error {
	return i.storageUnlock(ctx, name)
}

// HandleEvent calls event-handler.handle. Returns ErrEventAborted if the
// guest aborted the event.
func (i *Instance) HandleEvent(ctx context.Context, ev Event) error {
	return i.handleEvent(ctx, ev)
}

// GetUpstreams calls upstream-source.get-upstreams with a request scope.
func (i *Instance) GetUpstreams(ctx context.Context, scope *HTTPScope) ([]Upstream, error) {
	return i.getUpstreams(ctx, scope)
}

// DNS* call the dns-provider interface (libdns semantics; each returns the
// records actually affected).
func (i *Instance) DNSGetRecords(ctx context.Context, zone string) ([]DNSRecord, error) {
	return i.dnsGetRecords(ctx, zone)
}
func (i *Instance) DNSAppendRecords(ctx context.Context, zone string, recs []DNSRecord) ([]DNSRecord, error) {
	return i.dnsAppendRecords(ctx, zone, recs)
}
func (i *Instance) DNSSetRecords(ctx context.Context, zone string, recs []DNSRecord) ([]DNSRecord, error) {
	return i.dnsSetRecords(ctx, zone, recs)
}
func (i *Instance) DNSDeleteRecords(ctx context.Context, zone string, recs []DNSRecord) ([]DNSRecord, error) {
	return i.dnsDeleteRecords(ctx, zone, recs)
}

// File is a handle to a guest-owned open file (caddy:plugin/fs.file).
type File struct {
	m      *Module
	handle uint32
}

// Read calls fs.file.read. Returns data and eof.
func (f *File) Read(ctx context.Context, max uint64) ([]byte, bool, error) {
	return f.read(ctx, max)
}

// Seek calls fs.file.seek. whence: 0=start, 1=current, 2=end.
func (f *File) Seek(ctx context.Context, offset int64, whence uint8) (uint64, error) {
	return f.seek(ctx, offset, whence)
}

// Stat calls fs.file.stat.
func (f *File) Stat(ctx context.Context) (FileInfo, error) { return f.stat(ctx) }

// Close drops the guest-owned file resource.
func (f *File) Close(ctx context.Context) error { return f.closeFile(ctx) }
