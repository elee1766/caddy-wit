package gen

// exports.go wraps the guest's exported functions in typed methods. Every
// method lowers its arguments through abi.CallExport with the descriptor
// tables from descriptors.go and lifts the untyped result back into the
// types.go structs.
//
// Error contract: host-side failures (traps, missing exports, malformed
// results) are returned as ordinary errors; a guest err(string) case is
// returned as *abi.GuestError; richer guest error payloads (plugin-error,
// handler-error) are returned as typed values with a nil error.

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero/api"

	"github.com/elee1766/caddy-wit/pkg/abi"
)

// Export-name prefixes for each guest-exported interface
// ("caddy:plugin/<iface>@0.1.0#").
const (
	ExportPrefixManifest        = "caddy:plugin/manifest@0.1.0#"
	ExportPrefixLifecycle       = "caddy:plugin/lifecycle@0.1.0#"
	ExportPrefixConfig          = "caddy:plugin/config@0.1.0#"
	ExportPrefixHTTPHandler     = "caddy:plugin/http-handler@0.1.0#"
	ExportPrefixHTTPMatcher     = "caddy:plugin/http-matcher@0.1.0#"
	ExportPrefixFS              = "caddy:plugin/fs@0.1.0#"
	ExportPrefixTLSIssuer       = "caddy:plugin/tls-issuer@0.1.0#"
	ExportPrefixTLSCertLoader   = "caddy:plugin/tls-cert-loader@0.1.0#"
	ExportPrefixStorageProvider = "caddy:plugin/storage-provider@0.1.0#"
	ExportPrefixEventHandler    = "caddy:plugin/event-handler@0.1.0#"
	ExportPrefixDNSProvider     = "caddy:plugin/dns-provider@0.1.0#"
	ExportPrefixUpstreamSource  = "caddy:plugin/upstream-source@0.1.0#"
)

// Exports is a typed view over one instantiated guest module's exports.
type Exports struct {
	mod api.Module
}

// NewExports wraps mod.
func NewExports(mod api.Module) *Exports {
	return &Exports{mod: mod}
}

// --- shared result plumbing ---

func asRes(raw any, name string) (abi.Res, error) {
	r, ok := raw.(abi.Res)
	if !ok {
		return abi.Res{}, fmt.Errorf("gen: %s: expected abi.Res result, got %T", name, raw)
	}
	return r, nil
}

// guestStrErr converts the err(string) case of a result into *abi.GuestError.
func guestStrErr(r abi.Res, name string) error {
	msg, ok := r.Val.(string)
	if !ok {
		return fmt.Errorf("gen: %s: err payload: expected string, got %T", name, r.Val)
	}
	return &abi.GuestError{Message: msg}
}

// callVoidStr calls a guest export returning result<_, string>.
func (e *Exports) callVoidStr(ctx context.Context, name string, ft *abi.FuncType, args []any) error {
	raw, err := abi.CallExport(ctx, e.mod, name, ft, args)
	if err != nil {
		return err
	}
	r, err := asRes(raw, name)
	if err != nil {
		return err
	}
	if r.IsErr {
		return guestStrErr(r, name)
	}
	return nil
}

// callOkStr calls a guest export returning result<T, string> and hands back
// the ok payload.
func (e *Exports) callOkStr(ctx context.Context, name string, ft *abi.FuncType, args []any) (any, error) {
	raw, err := abi.CallExport(ctx, e.mod, name, ft, args)
	if err != nil {
		return nil, err
	}
	r, err := asRes(raw, name)
	if err != nil {
		return nil, err
	}
	if r.IsErr {
		return nil, guestStrErr(r, name)
	}
	return r.Val, nil
}

// liftOwn implements the canonical-ABI lift_own step for an own<T> returned
// by the guest for a resource type the guest itself implements: the guest
// hands back a handle it minted via [resource-new]; the host pops that table
// entry and takes ownership of the REP. From then on the host identifies the
// resource by rep: borrows passed back into the guest are lowered to the rep
// directly (lower_borrow when the callee owns the resource type), and
// dropping calls the guest's [dtor] with the rep.
func (e *Exports) liftOwn(ctx context.Context, tableKey string, handle uint32) (uint32, error) {
	tables := abi.TablesFromContext(ctx)
	if tables == nil {
		return 0, fmt.Errorf("gen: no resource tables in context lifting own<%s>", tableKey)
	}
	rep, ok := tables.Table(tableKey).Remove(handle)
	if !ok {
		return 0, fmt.Errorf("gen: guest returned unknown %s handle %d", tableKey, handle)
	}
	return rep, nil
}

// dropOwnedResource runs the guest destructor export on a rep obtained via
// liftOwn. A missing destructor export is treated as a no-op (some guests
// inline destruction elsewhere).
func (e *Exports) dropOwnedResource(ctx context.Context, dtorExport string, rep uint32) error {
	if e == nil || e.mod == nil {
		return nil
	}
	dtor := e.mod.ExportedFunction(dtorExport)
	if dtor == nil {
		return nil
	}
	if _, err := dtor.Call(ctx, uint64(rep)); err != nil {
		return fmt.Errorf("gen: calling %s: %w", dtorExport, err)
	}
	return nil
}

// --- manifest ---

// ManifestDescribe calls manifest.describe: func() -> plugin-info.
func (e *Exports) ManifestDescribe(ctx context.Context) (PluginInfo, error) {
	const name = ExportPrefixManifest + "describe"
	raw, err := abi.CallExport(ctx, e.mod, name, ftManifestDescribe, nil)
	if err != nil {
		return PluginInfo{}, err
	}
	return pluginInfoFromAny(raw)
}

// --- lifecycle ---

// LifecycleInstanceProvision calls lifecycle.[static]instance.provision:
// func(module-id: string, config: json) -> result<own<instance>, string>.
func (e *Exports) LifecycleInstanceProvision(ctx context.Context, moduleID string, configJSON string) (uint32, error) {
	const name = ExportPrefixLifecycle + "[static]instance.provision"
	v, err := e.callOkStr(ctx, name, ftLifecycleProvision, []any{moduleID, configJSON})
	if err != nil {
		return 0, err
	}
	handle, err := asU32(v, name+" result")
	if err != nil {
		return 0, err
	}
	return e.liftOwn(ctx, "lifecycle#instance", handle)
}

// LifecycleInstanceValidate calls lifecycle.[method]instance.validate:
// func(self) -> result<_, string>.
func (e *Exports) LifecycleInstanceValidate(ctx context.Context, self uint32) error {
	return e.callVoidStr(ctx, ExportPrefixLifecycle+"[method]instance.validate", ftLifecycleValidate, []any{self})
}

// LifecycleInstanceCleanup calls lifecycle.[method]instance.cleanup:
// func(self).
func (e *Exports) LifecycleInstanceCleanup(ctx context.Context, self uint32) error {
	_, err := abi.CallExport(ctx, e.mod, ExportPrefixLifecycle+"[method]instance.cleanup", ftLifecycleCleanup, []any{self})
	return err
}

// LifecycleInstanceDrop releases an own<instance> handle: it removes the
// handle from the module's resource table and invokes the guest's
// [dtor]instance export with the rep. Unknown handles are treated as
// already dropped.
func (e *Exports) LifecycleInstanceDrop(ctx context.Context, rep uint32) error {
	return e.dropOwnedResource(ctx, ExportPrefixLifecycle+"[dtor]instance", rep)
}

// --- config ---

// ConfigUnmarshalCaddyfile calls config.unmarshal-caddyfile:
// func(module-id: string, tokens: list<token>) -> result<json, string>.
func (e *Exports) ConfigUnmarshalCaddyfile(ctx context.Context, moduleID string, tokens []Token) (string, error) {
	const name = ExportPrefixConfig + "unmarshal-caddyfile"
	v, err := e.callOkStr(ctx, name, ftConfigUnmarshalCaddyfile, []any{moduleID, tokensToAny(tokens)})
	if err != nil {
		return "", err
	}
	return asString(v, name+" result")
}

// --- http-handler ---

// HTTPHandlerServe calls http-handler.serve: func(inst, req, resp) ->
// result<_, plugin-error>. A guest-reported plugin-error is returned as a
// non-nil *PluginError with a nil error.
func (e *Exports) HTTPHandlerServe(ctx context.Context, inst, req, resp uint32) (*PluginError, error) {
	const name = ExportPrefixHTTPHandler + "serve"
	raw, err := abi.CallExport(ctx, e.mod, name, ftHTTPHandlerServe, []any{inst, req, resp})
	if err != nil {
		return nil, err
	}
	r, err := asRes(raw, name)
	if err != nil {
		return nil, err
	}
	if !r.IsErr {
		return nil, nil
	}
	pe, err := pluginErrorFromAny(r.Val)
	if err != nil {
		return nil, fmt.Errorf("gen: %s: %w", name, err)
	}
	return &pe, nil
}

// --- http-matcher ---

// HTTPMatcherMatches calls http-matcher.matches: func(inst, req) ->
// result<bool, string>.
func (e *Exports) HTTPMatcherMatches(ctx context.Context, inst, req uint32) (bool, error) {
	const name = ExportPrefixHTTPMatcher + "matches"
	v, err := e.callOkStr(ctx, name, ftHTTPMatcherMatches, []any{inst, req})
	if err != nil {
		return false, err
	}
	return asBool(v, name+" result")
}

// --- fs ---

// FSOpen calls fs.open: func(inst, path: string) -> result<own<file>, string>.
func (e *Exports) FSOpen(ctx context.Context, inst uint32, path string) (uint32, error) {
	const name = ExportPrefixFS + "open"
	v, err := e.callOkStr(ctx, name, ftFSOpen, []any{inst, path})
	if err != nil {
		return 0, err
	}
	handle, err := asU32(v, name+" result")
	if err != nil {
		return 0, err
	}
	return e.liftOwn(ctx, "fs#file", handle)
}

// FSStat calls fs.stat: func(inst, path: string) -> result<file-info, string>.
func (e *Exports) FSStat(ctx context.Context, inst uint32, path string) (FileInfo, error) {
	const name = ExportPrefixFS + "stat"
	v, err := e.callOkStr(ctx, name, ftFSStat, []any{inst, path})
	if err != nil {
		return FileInfo{}, err
	}
	return fileInfoFromAny(v)
}

// FSReadDir calls fs.read-dir: func(inst, path: string) ->
// result<list<file-info>, string>.
func (e *Exports) FSReadDir(ctx context.Context, inst uint32, path string) ([]FileInfo, error) {
	const name = ExportPrefixFS + "read-dir"
	v, err := e.callOkStr(ctx, name, ftFSReadDir, []any{inst, path})
	if err != nil {
		return nil, err
	}
	return fileInfosFromAny(v)
}

// FSFileRead calls fs.[method]file.read: func(self, max: u64) ->
// result<tuple<list<u8>, bool>, string>. The pair is (bytes, eof).
func (e *Exports) FSFileRead(ctx context.Context, self uint32, max uint64) (abi.Pair[[]byte, bool], error) {
	const name = ExportPrefixFS + "[method]file.read"
	v, err := e.callOkStr(ctx, name, ftFSFileRead, []any{self, max})
	if err != nil {
		return abi.Pair[[]byte, bool]{}, err
	}
	f, err := recordFields(v, 2, name+" result")
	if err != nil {
		return abi.Pair[[]byte, bool]{}, err
	}
	data, err := asBytes(f[0], name+" result.0")
	if err != nil {
		return abi.Pair[[]byte, bool]{}, err
	}
	eof, err := asBool(f[1], name+" result.1")
	if err != nil {
		return abi.Pair[[]byte, bool]{}, err
	}
	return abi.Pair[[]byte, bool]{V0: data, V1: eof}, nil
}

// FSFileSeek calls fs.[method]file.seek: func(self, offset: s64, whence: u8)
// -> result<u64, string>.
func (e *Exports) FSFileSeek(ctx context.Context, self uint32, offset int64, whence uint8) (uint64, error) {
	const name = ExportPrefixFS + "[method]file.seek"
	v, err := e.callOkStr(ctx, name, ftFSFileSeek, []any{self, offset, whence})
	if err != nil {
		return 0, err
	}
	return asU64(v, name+" result")
}

// FSFileStat calls fs.[method]file.stat: func(self) -> result<file-info, string>.
func (e *Exports) FSFileStat(ctx context.Context, self uint32) (FileInfo, error) {
	const name = ExportPrefixFS + "[method]file.stat"
	v, err := e.callOkStr(ctx, name, ftFSFileStat, []any{self})
	if err != nil {
		return FileInfo{}, err
	}
	return fileInfoFromAny(v)
}

// FSFileDrop releases an own<file> rep (obtained via FSOpen's lift_own) by
// invoking the guest's [dtor]file export.
func (e *Exports) FSFileDrop(ctx context.Context, rep uint32) error {
	return e.dropOwnedResource(ctx, ExportPrefixFS+"[dtor]file", rep)
}

// --- tls-issuer ---

// TLSIssuerIssuerKey calls tls-issuer.issuer-key: func(inst) -> string.
func (e *Exports) TLSIssuerIssuerKey(ctx context.Context, inst uint32) (string, error) {
	const name = ExportPrefixTLSIssuer + "issuer-key"
	raw, err := abi.CallExport(ctx, e.mod, name, ftTLSIssuerKey, []any{inst})
	if err != nil {
		return "", err
	}
	return asString(raw, name+" result")
}

// TLSIssuerIssue calls tls-issuer.issue: func(inst, csr-der: list<u8>) ->
// result<issued-certificate, string>.
func (e *Exports) TLSIssuerIssue(ctx context.Context, inst uint32, csrDER []byte) (IssuedCertificate, error) {
	const name = ExportPrefixTLSIssuer + "issue"
	if csrDER == nil {
		csrDER = []byte{}
	}
	v, err := e.callOkStr(ctx, name, ftTLSIssuerIssue, []any{inst, csrDER})
	if err != nil {
		return IssuedCertificate{}, err
	}
	return issuedCertificateFromAny(v)
}

// --- tls-cert-loader ---

// TLSCertLoaderLoadCertificates calls tls-cert-loader.load-certificates:
// func(inst) -> result<list<certificate-key-pair>, string>.
func (e *Exports) TLSCertLoaderLoadCertificates(ctx context.Context, inst uint32) ([]CertificateKeyPair, error) {
	const name = ExportPrefixTLSCertLoader + "load-certificates"
	v, err := e.callOkStr(ctx, name, ftTLSCertLoaderLoad, []any{inst})
	if err != nil {
		return nil, err
	}
	return certificateKeyPairsFromAny(v)
}

// --- storage-provider ---

// StorageProviderStore calls storage-provider.store: func(inst, key: string,
// value: list<u8>) -> result<_, string>.
func (e *Exports) StorageProviderStore(ctx context.Context, inst uint32, key string, value []byte) error {
	if value == nil {
		value = []byte{}
	}
	return e.callVoidStr(ctx, ExportPrefixStorageProvider+"store", ftSPStore, []any{inst, key, value})
}

// StorageProviderLoad calls storage-provider.load: func(inst, key: string) ->
// result<list<u8>, string>.
func (e *Exports) StorageProviderLoad(ctx context.Context, inst uint32, key string) ([]byte, error) {
	const name = ExportPrefixStorageProvider + "load"
	v, err := e.callOkStr(ctx, name, ftSPLoad, []any{inst, key})
	if err != nil {
		return nil, err
	}
	return asBytes(v, name+" result")
}

// StorageProviderDelete calls storage-provider.delete: func(inst, key: string)
// -> result<_, string>.
func (e *Exports) StorageProviderDelete(ctx context.Context, inst uint32, key string) error {
	return e.callVoidStr(ctx, ExportPrefixStorageProvider+"delete", ftSPDelete, []any{inst, key})
}

// StorageProviderExists calls storage-provider.exists: func(inst, key: string)
// -> bool.
func (e *Exports) StorageProviderExists(ctx context.Context, inst uint32, key string) (bool, error) {
	const name = ExportPrefixStorageProvider + "exists"
	raw, err := abi.CallExport(ctx, e.mod, name, ftSPExists, []any{inst, key})
	if err != nil {
		return false, err
	}
	return asBool(raw, name+" result")
}

// StorageProviderListKeys calls storage-provider.list-keys: func(inst,
// prefix: string, recursive: bool) -> result<list<string>, string>.
func (e *Exports) StorageProviderListKeys(ctx context.Context, inst uint32, prefix string, recursive bool) ([]string, error) {
	const name = ExportPrefixStorageProvider + "list-keys"
	v, err := e.callOkStr(ctx, name, ftSPListKeys, []any{inst, prefix, recursive})
	if err != nil {
		return nil, err
	}
	return stringsFromAny(v, name+" result")
}

// StorageProviderStat calls storage-provider.stat: func(inst, key: string) ->
// result<key-info, string>.
func (e *Exports) StorageProviderStat(ctx context.Context, inst uint32, key string) (KeyInfo, error) {
	const name = ExportPrefixStorageProvider + "stat"
	v, err := e.callOkStr(ctx, name, ftSPStat, []any{inst, key})
	if err != nil {
		return KeyInfo{}, err
	}
	return keyInfoFromAny(v)
}

// StorageProviderLock calls storage-provider.lock: func(inst, name: string) ->
// result<_, string>.
func (e *Exports) StorageProviderLock(ctx context.Context, inst uint32, name string) error {
	return e.callVoidStr(ctx, ExportPrefixStorageProvider+"lock", ftSPLock, []any{inst, name})
}

// StorageProviderUnlock calls storage-provider.unlock: func(inst,
// name: string) -> result<_, string>.
func (e *Exports) StorageProviderUnlock(ctx context.Context, inst uint32, name string) error {
	return e.callVoidStr(ctx, ExportPrefixStorageProvider+"unlock", ftSPUnlock, []any{inst, name})
}

// --- dns-provider ---

// DNSProviderGetRecords calls dns-provider.get-records: func(inst,
// zone: string) -> result<list<dns-record>, string>.
func (e *Exports) DNSProviderGetRecords(ctx context.Context, inst uint32, zone string) ([]DNSRecord, error) {
	const name = ExportPrefixDNSProvider + "get-records"
	v, err := e.callOkStr(ctx, name, ftDNSGetRecords, []any{inst, zone})
	if err != nil {
		return nil, err
	}
	return dnsRecordsFromAny(v)
}

// dnsMutateRecords is the shared body of the append/set/delete-records
// wrappers: func(inst, zone: string, records: list<dns-record>) ->
// result<list<dns-record>, string>.
func (e *Exports) dnsMutateRecords(ctx context.Context, name string, inst uint32, zone string, records []DNSRecord) ([]DNSRecord, error) {
	v, err := e.callOkStr(ctx, name, ftDNSMutateRecords, []any{inst, zone, dnsRecordsToAny(records)})
	if err != nil {
		return nil, err
	}
	return dnsRecordsFromAny(v)
}

// DNSProviderAppendRecords calls dns-provider.append-records.
func (e *Exports) DNSProviderAppendRecords(ctx context.Context, inst uint32, zone string, records []DNSRecord) ([]DNSRecord, error) {
	return e.dnsMutateRecords(ctx, ExportPrefixDNSProvider+"append-records", inst, zone, records)
}

// DNSProviderSetRecords calls dns-provider.set-records.
func (e *Exports) DNSProviderSetRecords(ctx context.Context, inst uint32, zone string, records []DNSRecord) ([]DNSRecord, error) {
	return e.dnsMutateRecords(ctx, ExportPrefixDNSProvider+"set-records", inst, zone, records)
}

// DNSProviderDeleteRecords calls dns-provider.delete-records.
func (e *Exports) DNSProviderDeleteRecords(ctx context.Context, inst uint32, zone string, records []DNSRecord) ([]DNSRecord, error) {
	return e.dnsMutateRecords(ctx, ExportPrefixDNSProvider+"delete-records", inst, zone, records)
}

// --- event-handler ---

// EventHandlerHandle calls event-handler.handle: func(inst, evt: event) ->
// result<_, handler-error>. A guest-reported handler-error is returned as a
// non-nil *HandlerError with a nil error.
func (e *Exports) EventHandlerHandle(ctx context.Context, inst uint32, ev Event) (*HandlerError, error) {
	const name = ExportPrefixEventHandler + "handle"
	raw, err := abi.CallExport(ctx, e.mod, name, ftEventHandlerHandle, []any{inst, eventToAny(ev)})
	if err != nil {
		return nil, err
	}
	r, err := asRes(raw, name)
	if err != nil {
		return nil, err
	}
	if !r.IsErr {
		return nil, nil
	}
	he, err := handlerErrorFromAny(r.Val)
	if err != nil {
		return nil, fmt.Errorf("gen: %s: %w", name, err)
	}
	return &he, nil
}

// --- upstream-source ---

// UpstreamSourceGetUpstreams calls upstream-source.get-upstreams:
// func(inst, req) -> result<list<upstream>, string>.
func (e *Exports) UpstreamSourceGetUpstreams(ctx context.Context, inst, req uint32) ([]Upstream, error) {
	const name = ExportPrefixUpstreamSource + "get-upstreams"
	v, err := e.callOkStr(ctx, name, ftUpstreamSourceGetUpstreams, []any{inst, req})
	if err != nil {
		return nil, err
	}
	return upstreamsFromAny(v)
}
