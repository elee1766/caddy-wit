package runtime

// calls.go implements the guest-call wrappers behind the public Module /
// Instance / File methods in api.go. Every wrapper follows the same shape:
// take the Module mutex (a wasm instance is single-threaded), refuse if the
// module is closed, prepare the guest context via callCtx, invoke the
// generated export wrapper, and convert wire types to public types.
//
// Errors returned from gen export wrappers are passed through as-is: traps
// and missing exports arrive as ordinary errors, guest string-errors arrive
// as *abi.GuestError (which implements error).

import (
	"context"
	"errors"

	"github.com/elee1766/caddy-wit/pkg/runtime/gen"
)

// guestExports must be called with m.internal.mu held.
func (m *Module) guestExports() (*gen.Exports, error) {
	if m == nil || m.internal.mod == nil || m.internal.exports == nil {
		return nil, errModuleClosed
	}
	return m.internal.exports, nil
}

// --- Module: manifest / lifecycle / config ---

func (m *Module) describe(ctx context.Context) (PluginInfo, error) {
	m.internal.mu.Lock()
	defer m.internal.mu.Unlock()
	exports, err := m.guestExports()
	if err != nil {
		return PluginInfo{}, err
	}
	gi, err := exports.ManifestDescribe(m.callCtx(ctx))
	if err != nil {
		return PluginInfo{}, err
	}
	return pluginInfoFromGen(gi), nil
}

func (m *Module) provision(ctx context.Context, moduleID, configJSON string) (*Instance, error) {
	m.internal.mu.Lock()
	defer m.internal.mu.Unlock()
	exports, err := m.guestExports()
	if err != nil {
		return nil, err
	}
	handle, err := exports.LifecycleInstanceProvision(m.callCtx(ctx), moduleID, configJSON)
	if err != nil {
		return nil, err
	}
	return &Instance{m: m, handle: handle}, nil
}

func (m *Module) unmarshalCaddyfile(ctx context.Context, moduleID string, tokens []Token) (string, error) {
	m.internal.mu.Lock()
	defer m.internal.mu.Unlock()
	exports, err := m.guestExports()
	if err != nil {
		return "", err
	}
	return exports.ConfigUnmarshalCaddyfile(m.callCtx(ctx), moduleID, tokensToGen(tokens))
}

// --- Instance: lifecycle ---

// live must be called with i.m.internal.mu held. Note: a handle of 0 is the
// cleaned-up sentinel; guest handles minted by the canonical-ABI resource
// tables start at 1.
func (i *Instance) live() (*gen.Exports, error) {
	if i == nil || i.m == nil {
		return nil, errInstanceClosed
	}
	exports, err := i.m.guestExports()
	if err != nil {
		return nil, err
	}
	if i.handle == 0 {
		return nil, errInstanceClosed
	}
	return exports, nil
}

func (i *Instance) validate(ctx context.Context) error {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return err
	}
	return exports.LifecycleInstanceValidate(i.m.callCtx(ctx), i.handle)
}

func (i *Instance) cleanup(ctx context.Context) error {
	if i == nil || i.m == nil {
		return nil
	}
	m := i.m
	m.internal.mu.Lock()
	defer m.internal.mu.Unlock()
	if i.handle == 0 {
		// Already cleaned up.
		return nil
	}
	handle := i.handle
	i.handle = 0
	exports, err := m.guestExports()
	if err != nil {
		// Module already closed: the guest instance died with it.
		return nil
	}
	ctx = m.callCtx(ctx)
	cerr := exports.LifecycleInstanceCleanup(ctx, handle)
	derr := exports.LifecycleInstanceDrop(ctx, handle)
	return errors.Join(cerr, derr)
}

// --- Instance: http ---

func (i *Instance) serveHTTP(ctx context.Context, scope *HTTPScope) error {
	if scope == nil {
		return errNilScope
	}
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return err
	}
	ctx = withScope(i.m.callCtx(ctx), scope)
	guestErr, err := exports.HTTPHandlerServe(ctx, i.handle, requestHandle, responseWriterHandle)
	if err != nil {
		return err
	}
	if guestErr != nil {
		return pluginErrorFromGen(guestErr)
	}
	return nil
}

func (i *Instance) matches(ctx context.Context, scope *HTTPScope) (bool, error) {
	if scope == nil {
		return false, errNilScope
	}
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return false, err
	}
	ctx = withScope(i.m.callCtx(ctx), scope)
	return exports.HTTPMatcherMatches(ctx, i.handle, requestHandle)
}

// --- Instance: fs ---

func (i *Instance) fsOpen(ctx context.Context, path string) (*File, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return nil, err
	}
	handle, err := exports.FSOpen(i.m.callCtx(ctx), i.handle, path)
	if err != nil {
		return nil, err
	}
	return &File{m: i.m, handle: handle}, nil
}

func (i *Instance) fsStat(ctx context.Context, path string) (FileInfo, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return FileInfo{}, err
	}
	fi, err := exports.FSStat(i.m.callCtx(ctx), i.handle, path)
	if err != nil {
		return FileInfo{}, err
	}
	return fileInfoFromGen(fi), nil
}

func (i *Instance) fsReadDir(ctx context.Context, path string) ([]FileInfo, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return nil, err
	}
	fis, err := exports.FSReadDir(i.m.callCtx(ctx), i.handle, path)
	if err != nil {
		return nil, err
	}
	return fileInfosFromGen(fis), nil
}

// --- Instance: tls ---

func (i *Instance) issuerKey(ctx context.Context) (string, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return "", err
	}
	return exports.TLSIssuerIssuerKey(i.m.callCtx(ctx), i.handle)
}

func (i *Instance) issue(ctx context.Context, csrDER []byte) (IssuedCertificate, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return IssuedCertificate{}, err
	}
	ic, err := exports.TLSIssuerIssue(i.m.callCtx(ctx), i.handle, csrDER)
	if err != nil {
		return IssuedCertificate{}, err
	}
	return issuedCertificateFromGen(ic), nil
}

func (i *Instance) loadCertificates(ctx context.Context) ([]CertificateKeyPair, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return nil, err
	}
	pairs, err := exports.TLSCertLoaderLoadCertificates(i.m.callCtx(ctx), i.handle)
	if err != nil {
		return nil, err
	}
	return certificateKeyPairsFromGen(pairs), nil
}

// --- Instance: storage-provider ---

func (i *Instance) storageStore(ctx context.Context, key string, value []byte) error {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return err
	}
	return exports.StorageProviderStore(i.m.callCtx(ctx), i.handle, key, value)
}

func (i *Instance) storageLoad(ctx context.Context, key string) ([]byte, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return nil, err
	}
	return exports.StorageProviderLoad(i.m.callCtx(ctx), i.handle, key)
}

func (i *Instance) storageDelete(ctx context.Context, key string) error {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return err
	}
	return exports.StorageProviderDelete(i.m.callCtx(ctx), i.handle, key)
}

func (i *Instance) storageExists(ctx context.Context, key string) (bool, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return false, err
	}
	return exports.StorageProviderExists(i.m.callCtx(ctx), i.handle, key)
}

func (i *Instance) storageList(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return nil, err
	}
	return exports.StorageProviderListKeys(i.m.callCtx(ctx), i.handle, prefix, recursive)
}

func (i *Instance) storageStat(ctx context.Context, key string) (KeyInfo, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return KeyInfo{}, err
	}
	ki, err := exports.StorageProviderStat(i.m.callCtx(ctx), i.handle, key)
	if err != nil {
		return KeyInfo{}, err
	}
	return keyInfoFromGen(ki), nil
}

func (i *Instance) storageLock(ctx context.Context, name string) error {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return err
	}
	return exports.StorageProviderLock(i.m.callCtx(ctx), i.handle, name)
}

func (i *Instance) storageUnlock(ctx context.Context, name string) error {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return err
	}
	return exports.StorageProviderUnlock(i.m.callCtx(ctx), i.handle, name)
}

// --- Instance: events ---

func (i *Instance) handleEvent(ctx context.Context, ev Event) error {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return err
	}
	herr, err := exports.EventHandlerHandle(i.m.callCtx(ctx), i.handle, eventToGen(ev))
	if err != nil {
		return err
	}
	if herr == nil {
		return nil
	}
	switch herr.Tag {
	case gen.HandlerErrorAborted:
		return ErrEventAborted
	default: // gen.HandlerErrorMessage
		return errors.New(herr.Message)
	}
}

// --- Instance: upstream-source ---

func (i *Instance) getUpstreams(ctx context.Context, scope *HTTPScope) ([]Upstream, error) {
	if scope == nil {
		return nil, errNilScope
	}
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return nil, err
	}
	ctx = withScope(i.m.callCtx(ctx), scope)
	gus, err := exports.UpstreamSourceGetUpstreams(ctx, i.handle, requestHandle)
	if err != nil {
		return nil, err
	}
	return upstreamsFromGen(gus), nil
}

// --- Instance: dns-provider ---

func (i *Instance) dnsGetRecords(ctx context.Context, zone string) ([]DNSRecord, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return nil, err
	}
	recs, err := exports.DNSProviderGetRecords(i.m.callCtx(ctx), i.handle, zone)
	if err != nil {
		return nil, err
	}
	return dnsRecordsFromGen(recs), nil
}

func (i *Instance) dnsAppendRecords(ctx context.Context, zone string, recs []DNSRecord) ([]DNSRecord, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return nil, err
	}
	out, err := exports.DNSProviderAppendRecords(i.m.callCtx(ctx), i.handle, zone, dnsRecordsToGen(recs))
	if err != nil {
		return nil, err
	}
	return dnsRecordsFromGen(out), nil
}

func (i *Instance) dnsSetRecords(ctx context.Context, zone string, recs []DNSRecord) ([]DNSRecord, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return nil, err
	}
	out, err := exports.DNSProviderSetRecords(i.m.callCtx(ctx), i.handle, zone, dnsRecordsToGen(recs))
	if err != nil {
		return nil, err
	}
	return dnsRecordsFromGen(out), nil
}

func (i *Instance) dnsDeleteRecords(ctx context.Context, zone string, recs []DNSRecord) ([]DNSRecord, error) {
	i.m.internal.mu.Lock()
	defer i.m.internal.mu.Unlock()
	exports, err := i.live()
	if err != nil {
		return nil, err
	}
	out, err := exports.DNSProviderDeleteRecords(i.m.callCtx(ctx), i.handle, zone, dnsRecordsToGen(recs))
	if err != nil {
		return nil, err
	}
	return dnsRecordsFromGen(out), nil
}

// --- File ---

// liveFile must be called with f.m.internal.mu held.
func (f *File) liveFile() (*gen.Exports, error) {
	if f == nil || f.m == nil {
		return nil, errFileClosed
	}
	exports, err := f.m.guestExports()
	if err != nil {
		return nil, err
	}
	if f.handle == 0 {
		return nil, errFileClosed
	}
	return exports, nil
}

func (f *File) read(ctx context.Context, max uint64) ([]byte, bool, error) {
	f.m.internal.mu.Lock()
	defer f.m.internal.mu.Unlock()
	exports, err := f.liveFile()
	if err != nil {
		return nil, false, err
	}
	pair, err := exports.FSFileRead(f.m.callCtx(ctx), f.handle, max)
	if err != nil {
		return nil, false, err
	}
	return pair.V0, pair.V1, nil
}

func (f *File) seek(ctx context.Context, offset int64, whence uint8) (uint64, error) {
	f.m.internal.mu.Lock()
	defer f.m.internal.mu.Unlock()
	exports, err := f.liveFile()
	if err != nil {
		return 0, err
	}
	return exports.FSFileSeek(f.m.callCtx(ctx), f.handle, offset, whence)
}

func (f *File) stat(ctx context.Context) (FileInfo, error) {
	f.m.internal.mu.Lock()
	defer f.m.internal.mu.Unlock()
	exports, err := f.liveFile()
	if err != nil {
		return FileInfo{}, err
	}
	fi, err := exports.FSFileStat(f.m.callCtx(ctx), f.handle)
	if err != nil {
		return FileInfo{}, err
	}
	return fileInfoFromGen(fi), nil
}

func (f *File) closeFile(ctx context.Context) error {
	if f == nil || f.m == nil {
		return nil
	}
	f.m.internal.mu.Lock()
	defer f.m.internal.mu.Unlock()
	if f.handle == 0 {
		return nil
	}
	handle := f.handle
	f.handle = 0
	exports, err := f.m.guestExports()
	if err != nil {
		// Module already closed: the guest file died with it.
		return nil
	}
	return exports.FSFileDrop(f.m.callCtx(ctx), handle)
}
