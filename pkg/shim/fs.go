package shim

import (
	"context"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/elee1766/caddy-wit/pkg/runtime"
)

// FS adapts a wasm plugin module in the caddy.fs.* namespace to io/fs.FS
// (plus fs.StatFS and fs.ReadDirFS), which is what Caddy expects of
// filesystem modules (see caddy.FileSystems).
//
// File operations use context.Background(): guest files live for the
// lifetime of the provisioned module, not for any single request.
type FS struct {
	shimCore
}

func newFS(lp *LoadedPlugin, moduleID string) *FS {
	return &FS{shimCore{lp: lp, moduleID: moduleID}}
}

// CaddyModule returns the Caddy module information.
func (f *FS) CaddyModule() caddy.ModuleInfo {
	lp, id := f.lp, f.moduleID
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID(id),
		New: func() caddy.Module { return newFS(lp, id) },
	}
}

// Provision implements caddy.Provisioner.
func (f *FS) Provision(ctx caddy.Context) error {
	return f.provisionInstance(ctx, true)
}

// Validate implements caddy.Validator.
func (f *FS) Validate() error { return f.validateInstance() }

// Cleanup implements caddy.CleanerUpper.
func (f *FS) Cleanup() error { return f.cleanupInstance() }

// Open implements fs.FS.
func (f *FS) Open(name string) (fs.File, error) {
	if f.inst == nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrClosed}
	}
	file, err := f.inst.FSOpen(context.Background(), name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: mapGuestFSErr(err)}
	}
	return &wasmFile{f: file, name: name}, nil
}

// Stat implements fs.StatFS.
func (f *FS) Stat(name string) (fs.FileInfo, error) {
	if f.inst == nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrClosed}
	}
	fi, err := f.inst.FSStat(context.Background(), name)
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: mapGuestFSErr(err)}
	}
	return fileInfo{fi}, nil
}

// ReadDir implements fs.ReadDirFS.
func (f *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	if f.inst == nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrClosed}
	}
	infos, err := f.inst.FSReadDir(context.Background(), name)
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: mapGuestFSErr(err)}
	}
	entries := make([]fs.DirEntry, len(infos))
	for i, fi := range infos {
		entries[i] = dirEntry{fileInfo{fi}}
	}
	return entries, nil
}

// mapGuestFSErr maps guest error strings onto fs sentinel errors so that
// errors.Is(err, fs.ErrNotExist) works for callers (e.g. the file server's
// 404 handling).
//
// Convention: the WIT fs interface returns plain strings, so we match
// heuristically on an "ENOENT" prefix or a "not found"/"no such file"
// substring (case-insensitive). TODO(wit-v0.2): replace with a structured
// error-code variant in the WIT so this mapping is exact.
func mapGuestFSErr(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.HasPrefix(msg, "enoent") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no such file") {
		return fs.ErrNotExist
	}
	return err
}

// wasmFile adapts a guest-owned file handle to fs.File. It also implements
// io.Seeker; guests that don't support seeking return an error from Seek,
// which callers like http.ServeContent handle by disabling range requests.
type wasmFile struct {
	f    *runtime.File
	name string
	// buf holds bytes the guest returned beyond what the last Read consumed.
	buf []byte
	eof bool
}

// Read implements io.Reader over the guest's chunked read export,
// buffering any remainder if the guest returns more than requested.
func (wf *wasmFile) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(wf.buf) == 0 && !wf.eof {
		data, eof, err := wf.f.Read(context.Background(), uint64(len(p)))
		if err != nil {
			return 0, &fs.PathError{Op: "read", Path: wf.name, Err: err}
		}
		wf.buf = data
		wf.eof = eof
	}
	n := copy(p, wf.buf)
	wf.buf = wf.buf[n:]
	if n == 0 && wf.eof {
		return 0, io.EOF
	}
	return n, nil
}

// Seek implements io.Seeker. Guests may not support seeking, in which case
// the guest's error is returned and callers fall back to sequential reads.
func (wf *wasmFile) Seek(offset int64, whence int) (int64, error) {
	if whence < io.SeekStart || whence > io.SeekEnd {
		return 0, &fs.PathError{Op: "seek", Path: wf.name, Err: fs.ErrInvalid}
	}
	pos, err := wf.f.Seek(context.Background(), offset, uint8(whence))
	if err != nil {
		return 0, err
	}
	// Any buffered read-ahead is stale after a successful seek.
	wf.buf = nil
	wf.eof = false
	return int64(pos), nil
}

// Stat implements fs.File.
func (wf *wasmFile) Stat() (fs.FileInfo, error) {
	fi, err := wf.f.Stat(context.Background())
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: wf.name, Err: mapGuestFSErr(err)}
	}
	return fileInfo{fi}, nil
}

// Close implements fs.File, dropping the guest-owned resource.
func (wf *wasmFile) Close() error {
	return wf.f.Close(context.Background())
}

// fileInfo adapts runtime.FileInfo to fs.FileInfo.
type fileInfo struct {
	fi runtime.FileInfo
}

func (i fileInfo) Name() string { return i.fi.Name }
func (i fileInfo) Size() int64  { return int64(i.fi.Size) }

// Mode maps the guest's Unix-style mode bits: permission bits carry over
// directly; the directory flag is taken from FileInfo.Dir since Go's
// fs.FileMode type bits don't match the Unix S_IF* encoding.
func (i fileInfo) Mode() fs.FileMode {
	m := fs.FileMode(i.fi.Mode & 0o777)
	if i.fi.Dir {
		m |= fs.ModeDir
	}
	return m
}

func (i fileInfo) ModTime() time.Time { return i.fi.ModTime }
func (i fileInfo) IsDir() bool        { return i.fi.Dir }
func (i fileInfo) Sys() any           { return nil }

// dirEntry adapts runtime.FileInfo to fs.DirEntry.
type dirEntry struct {
	fileInfo
}

func (d dirEntry) Type() fs.FileMode          { return d.Mode().Type() }
func (d dirEntry) Info() (fs.FileInfo, error) { return d.fileInfo, nil }

// Interface guards
var (
	_ caddy.Provisioner  = (*FS)(nil)
	_ caddy.Validator    = (*FS)(nil)
	_ caddy.CleanerUpper = (*FS)(nil)
	_ fs.FS              = (*FS)(nil)
	_ fs.StatFS          = (*FS)(nil)
	_ fs.ReadDirFS       = (*FS)(nil)
	_ fs.File            = (*wasmFile)(nil)
	_ io.ReadSeeker      = (*wasmFile)(nil)
	_ fs.FileInfo        = fileInfo{}
	_ fs.DirEntry        = dirEntry{}
)
