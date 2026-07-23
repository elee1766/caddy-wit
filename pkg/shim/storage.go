package shim

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/elee1766/caddy-wit/pkg/runtime"
)

// Storage adapts a wasm plugin module in the caddy.storage.* namespace to
// caddy.StorageConverter: the guest acts as a certmagic.Storage backend.
type Storage struct {
	shimCore
}

func newStorage(lp *LoadedPlugin, moduleID string) *Storage {
	return &Storage{shimCore{lp: lp, moduleID: moduleID}}
}

// CaddyModule returns the Caddy module information.
func (s *Storage) CaddyModule() caddy.ModuleInfo {
	lp, id := s.lp, s.moduleID
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID(id),
		New: func() caddy.Module { return newStorage(lp, id) },
	}
}

// Provision implements caddy.Provisioner. Storage modules are provisioned
// before apps are loaded, so the guest gets no emit-event host import
// (ctx.App("events") at this stage would force premature app loading).
func (s *Storage) Provision(ctx caddy.Context) error {
	return s.provisionInstance(ctx, false)
}

// Validate implements caddy.Validator.
func (s *Storage) Validate() error { return s.validateInstance() }

// Cleanup implements caddy.CleanerUpper.
func (s *Storage) Cleanup() error { return s.cleanupInstance() }

// CertMagicStorage implements caddy.StorageConverter.
//
// Interface verified against caddy v2.11.4:
//
//	type StorageConverter interface { CertMagicStorage() (certmagic.Storage, error) }
func (s *Storage) CertMagicStorage() (certmagic.Storage, error) {
	if s.inst == nil {
		return nil, fmt.Errorf("module %s: wasm instance not provisioned", s.moduleID)
	}
	return &storageAdapter{moduleID: s.moduleID, inst: s.inst}, nil
}

// storageAdapter implements certmagic.Storage over the guest's
// storage-provider exports.
//
// Signatures verified against certmagic v0.25.3 (storage.go):
//
//	Store(ctx, key, value) error; Load(ctx, key) ([]byte, error)
//	Delete(ctx, key) error; Exists(ctx, key) bool
//	List(ctx, path, recursive) ([]string, error); Stat(ctx, key) (KeyInfo, error)
//	Lock(ctx, name) error; Unlock(ctx, name) error
type storageAdapter struct {
	moduleID string
	inst     *runtime.Instance
}

func (a *storageAdapter) Store(ctx context.Context, key string, value []byte) error {
	return a.inst.StorageStore(ctx, key, value)
}

func (a *storageAdapter) Load(ctx context.Context, key string) ([]byte, error) {
	data, err := a.inst.StorageLoad(ctx, key)
	if err != nil {
		return nil, mapGuestStorageErr(err)
	}
	return data, nil
}

func (a *storageAdapter) Delete(ctx context.Context, key string) error {
	return a.inst.StorageDelete(ctx, key)
}

// Exists returns false on guest errors: certmagic's Exists has no error
// return and treats "unknown" as absent.
func (a *storageAdapter) Exists(ctx context.Context, key string) bool {
	ok, err := a.inst.StorageExists(ctx, key)
	if err != nil {
		return false
	}
	return ok
}

func (a *storageAdapter) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	keys, err := a.inst.StorageList(ctx, prefix, recursive)
	if err != nil {
		return nil, mapGuestStorageErr(err)
	}
	return keys, nil
}

func (a *storageAdapter) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	ki, err := a.inst.StorageStat(ctx, key)
	if err != nil {
		return certmagic.KeyInfo{}, mapGuestStorageErr(err)
	}
	return certmagic.KeyInfo{
		Key:        ki.Key,
		Modified:   ki.Modified,
		Size:       ki.Size,
		IsTerminal: ki.Terminal,
	}, nil
}

func (a *storageAdapter) Lock(ctx context.Context, name string) error {
	return a.inst.StorageLock(ctx, name)
}

func (a *storageAdapter) Unlock(ctx context.Context, name string) error {
	return a.inst.StorageUnlock(ctx, name)
}

// mapGuestStorageErr maps guest "not found" error strings to fs.ErrNotExist,
// which certmagic requires from Load/Stat for missing keys. Same string
// heuristic (and same WIT v0.2 TODO) as mapGuestFSErr.
func mapGuestStorageErr(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.HasPrefix(msg, "enoent") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "does not exist") {
		return fs.ErrNotExist
	}
	return err
}

// Interface guards
var (
	_ caddy.Provisioner      = (*Storage)(nil)
	_ caddy.Validator        = (*Storage)(nil)
	_ caddy.CleanerUpper     = (*Storage)(nil)
	_ caddy.StorageConverter = (*Storage)(nil)
	_ certmagic.Storage      = (*storageAdapter)(nil)
)
