package runtime

// host.go implements gen.Host: the host side of the caddy:plugin import
// interfaces (log, replacer, host-storage, host-events, http-types). One
// hostImpl is bound per Module and resolves everything through the Module's
// Env; the live request/response pair for http-types calls is resolved from
// the *HTTPScope placed on the context by serveHTTP/matches.
//
// These methods are invoked re-entrantly while the Module mutex is held by
// the in-flight guest call, so they must not touch the mutex. They must also
// never panic: missing scope or missing Env capabilities degrade to zero
// values or errors, logged at debug where a logger is available.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/elee1766/caddy-wit/pkg/abi"
	"github.com/elee1766/caddy-wit/pkg/runtime/gen"
)

var (
	errStorageUnavailable = errors.New("caddywit: storage not available")
	errEventsUnavailable  = errors.New("caddywit: event emission not available")
	errNoResponseWriter   = errors.New("caddywit: no response writer in scope")
	errUnknownTCPConn     = errors.New("caddywit: unknown tcp connection handle")

	errHTTPPermission = errors.New(`permission denied: plugin lacks "http" permission`)
	errTCPPermission  = errors.New(`permission denied: plugin lacks "tcp" permission`)
)

// maxBodyChunk caps the buffer allocated for a single read-body call, so a
// guest asking for u64::MAX bytes cannot force a huge allocation. Shorter
// reads simply return eof=false and the guest calls again.
const maxBodyChunk = 1 << 20

const (
	// defaultNetTimeout is the host-http/host-tcp timeout applied when the
	// guest does not specify one.
	defaultNetTimeout = 30 * time.Second
	// defaultMaxResponseBytes caps host-http response bodies when the guest
	// does not specify max-response-bytes.
	defaultMaxResponseBytes = 16 << 20
	// maxBufferedResponseBytes caps the body recorded by next-buffered.
	maxBufferedResponseBytes = 16 << 20
	// maxTCPReadChunk caps the buffer allocated for a single tcp read.
	maxTCPReadChunk = 1 << 20
)

// defaultHTTPClient serves host-http requests when Env.HTTPClient is nil.
// Created once; safe for concurrent use.
var defaultHTTPClient = &http.Client{Timeout: defaultNetTimeout}

type hostImpl struct {
	m *Module
}

var _ gen.Host = hostImpl{}

func (h hostImpl) env() *Env { return h.m.env() }

// debugLog logs a host-side anomaly at debug level, if a logger exists.
func (h hostImpl) debugLog(msg string, fields ...zap.Field) {
	if l := h.env().Logger; l != nil {
		l.Debug(msg, fields...)
	}
}

// scope resolves the current HTTP scope, or nil (logged at debug) when an
// http-types method is called outside a serveHTTP/matches call.
func (h hostImpl) scope(ctx context.Context) *HTTPScope {
	s := scopeFrom(ctx)
	if s == nil {
		h.debugLog("caddywit: http-types host call outside request scope")
	}
	return s
}

func (h hostImpl) request(ctx context.Context) *http.Request {
	if s := h.scope(ctx); s != nil {
		return s.R
	}
	return nil
}

func (h hostImpl) responseWriter(ctx context.Context) http.ResponseWriter {
	if s := h.scope(ctx); s != nil {
		return s.W
	}
	return nil
}

// --- log ---

func (h hostImpl) Log(ctx context.Context, lvl gen.Level, msg string, fields []abi.Pair[string, string]) {
	logger := h.env().Logger
	if logger == nil {
		return
	}
	zf := make([]zap.Field, 0, len(fields))
	for _, f := range fields {
		zf = append(zf, zap.String(f.V0, f.V1))
	}
	switch lvl {
	case gen.LevelDebug:
		logger.Debug(msg, zf...)
	case gen.LevelWarn:
		logger.Warn(msg, zf...)
	case gen.LevelError:
		logger.Error(msg, zf...)
	default: // gen.LevelInfo and anything unknown
		logger.Info(msg, zf...)
	}
}

// --- replacer ---

func (h hostImpl) ReplaceAll(ctx context.Context, input string, empty string) string {
	if fn := h.env().Replace; fn != nil {
		return fn(input, empty)
	}
	return input
}

func (h hostImpl) Get(ctx context.Context, key string) *string {
	fn := h.env().GetVar
	if fn == nil {
		return nil
	}
	v, ok := fn(key)
	if !ok {
		return nil
	}
	return &v
}

// --- host-storage ---

func (h hostImpl) Store(ctx context.Context, key string, value []byte) error {
	st := h.env().Storage
	if st == nil {
		return errStorageUnavailable
	}
	return st.Store(ctx, key, value)
}

func (h hostImpl) Load(ctx context.Context, key string) ([]byte, error) {
	st := h.env().Storage
	if st == nil {
		return nil, errStorageUnavailable
	}
	return st.Load(ctx, key)
}

func (h hostImpl) Delete(ctx context.Context, key string) error {
	st := h.env().Storage
	if st == nil {
		return errStorageUnavailable
	}
	return st.Delete(ctx, key)
}

func (h hostImpl) Exists(ctx context.Context, key string) bool {
	st := h.env().Storage
	if st == nil {
		return false
	}
	return st.Exists(ctx, key)
}

func (h hostImpl) ListKeys(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	st := h.env().Storage
	if st == nil {
		return nil, errStorageUnavailable
	}
	return st.List(ctx, prefix, recursive)
}

func (h hostImpl) Stat(ctx context.Context, key string) (gen.KeyInfo, error) {
	st := h.env().Storage
	if st == nil {
		return gen.KeyInfo{}, errStorageUnavailable
	}
	ki, err := st.Stat(ctx, key)
	if err != nil {
		return gen.KeyInfo{}, err
	}
	return gen.KeyInfo{
		Key:      ki.Key,
		Modified: ki.Modified.UnixMilli(),
		Size:     ki.Size,
		Terminal: ki.IsTerminal,
	}, nil
}

func (h hostImpl) Lock(ctx context.Context, name string) error {
	st := h.env().Storage
	if st == nil {
		return errStorageUnavailable
	}
	return st.Lock(ctx, name)
}

func (h hostImpl) Unlock(ctx context.Context, name string) error {
	st := h.env().Storage
	if st == nil {
		return errStorageUnavailable
	}
	return st.Unlock(ctx, name)
}

// --- host-kv ---

// kvFor returns the KVStore for the given key. Keys prefixed with "shared:"
// route to the global SharedKV (accessible by all plugins and native Go
// code); all other keys route to the per-plugin KV.
const sharedPrefix = "shared:"

func (h hostImpl) kvFor(key string) (*KVStore, string) {
	if strings.HasPrefix(key, sharedPrefix) {
		return h.env().SharedKV, strings.TrimPrefix(key, sharedPrefix)
	}
	return h.env().KV, key
}

func (h hostImpl) KVGet(ctx context.Context, key string) []byte {
	kv, k := h.kvFor(key)
	if kv == nil {
		return nil
	}
	return kv.Get(k)
}

func (h hostImpl) KVSet(ctx context.Context, key string, value []byte, ttlMS *uint64) {
	kv, k := h.kvFor(key)
	if kv == nil {
		return
	}
	kv.Set(k, value, ttlMS)
}

func (h hostImpl) KVDelete(ctx context.Context, key string) {
	kv, k := h.kvFor(key)
	if kv == nil {
		return
	}
	kv.Delete(k)
}

func (h hostImpl) KVIncrement(ctx context.Context, key string, delta int64, ttlMS *uint64) int64 {
	kv, k := h.kvFor(key)
	if kv == nil {
		return delta
	}
	return kv.Increment(k, delta, ttlMS)
}

func (h hostImpl) KVExists(ctx context.Context, key string) bool {
	kv, k := h.kvFor(key)
	if kv == nil {
		return false
	}
	return kv.Exists(k)
}

// --- host-events ---

func (h hostImpl) Emit(ctx context.Context, name string, data string) error {
	fn := h.env().EmitEvent
	if fn == nil {
		return errEventsUnavailable
	}
	return fn(ctx, name, data)
}

// --- http-types: request ---

func (h hostImpl) RequestMethod(ctx context.Context, self uint32) string {
	if r := h.request(ctx); r != nil {
		return r.Method
	}
	return ""
}

func (h hostImpl) RequestURI(ctx context.Context, self uint32) string {
	if r := h.request(ctx); r != nil {
		return r.RequestURI
	}
	return ""
}

func (h hostImpl) RequestPath(ctx context.Context, self uint32) string {
	if r := h.request(ctx); r != nil && r.URL != nil {
		return r.URL.Path
	}
	return ""
}

func (h hostImpl) RequestQuery(ctx context.Context, self uint32) string {
	if r := h.request(ctx); r != nil && r.URL != nil {
		return r.URL.RawQuery
	}
	return ""
}

func (h hostImpl) RequestProtocol(ctx context.Context, self uint32) string {
	if r := h.request(ctx); r != nil {
		return r.Proto
	}
	return ""
}

func (h hostImpl) RequestHost(ctx context.Context, self uint32) string {
	if r := h.request(ctx); r != nil {
		return r.Host
	}
	return ""
}

func (h hostImpl) RequestRemoteAddr(ctx context.Context, self uint32) string {
	if r := h.request(ctx); r != nil {
		return r.RemoteAddr
	}
	return ""
}

func (h hostImpl) RequestHeaders(ctx context.Context, self uint32) []abi.Pair[string, string] {
	r := h.request(ctx)
	if r == nil {
		return nil
	}
	pairs := make([]abi.Pair[string, string], 0, len(r.Header))
	for name, values := range r.Header {
		for _, v := range values {
			pairs = append(pairs, abi.Pair[string, string]{V0: name, V1: v})
		}
	}
	return pairs
}

func (h hostImpl) RequestHeader(ctx context.Context, self uint32, name string) []string {
	if r := h.request(ctx); r != nil {
		return r.Header.Values(name)
	}
	return nil
}

func (h hostImpl) RequestSetHeader(ctx context.Context, self uint32, name string, value string) {
	if r := h.request(ctx); r != nil {
		r.Header.Set(name, value)
	}
}

func (h hostImpl) RequestAddHeader(ctx context.Context, self uint32, name string, value string) {
	if r := h.request(ctx); r != nil {
		r.Header.Add(name, value)
	}
}

func (h hostImpl) RequestRemoveHeader(ctx context.Context, self uint32, name string) {
	if r := h.request(ctx); r != nil {
		r.Header.Del(name)
	}
}

func (h hostImpl) RequestSetURI(ctx context.Context, self uint32, uri string) {
	r := h.request(ctx)
	if r == nil {
		return
	}
	u, err := url.ParseRequestURI(uri)
	if err != nil {
		// Per contract: invalid URIs are a no-op.
		h.debugLog("caddywit: set-uri with unparseable uri", zap.String("uri", uri), zap.Error(err))
		return
	}
	r.URL = u
	r.RequestURI = uri
}

func (h hostImpl) RequestSetMethod(ctx context.Context, self uint32, method string) {
	if r := h.request(ctx); r != nil {
		r.Method = method
	}
}

func (h hostImpl) RequestReadBody(ctx context.Context, self uint32, max uint64) (abi.Pair[[]byte, bool], error) {
	r := h.request(ctx)
	if r == nil || r.Body == nil {
		// No scope or no body: report immediate EOF rather than erroring.
		return abi.Pair[[]byte, bool]{V0: []byte{}, V1: true}, nil
	}
	if max == 0 {
		return abi.Pair[[]byte, bool]{V0: []byte{}, V1: false}, nil
	}
	n := max
	if n > maxBodyChunk {
		n = maxBodyChunk
	}
	buf := make([]byte, n)
	read, err := io.ReadFull(r.Body, buf)
	switch {
	case err == nil:
		return abi.Pair[[]byte, bool]{V0: buf[:read], V1: false}, nil
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return abi.Pair[[]byte, bool]{V0: buf[:read], V1: true}, nil
	default:
		return abi.Pair[[]byte, bool]{}, err
	}
}

func (h hostImpl) RequestReplace(ctx context.Context, self uint32, input string, empty string) string {
	// Prefer the request-scoped replacer (resolves {http.request.*}).
	scope := scopeFrom(ctx)
	if scope != nil && scope.Replace != nil {
		return scope.Replace(input, empty)
	}
	// Fallback to env-level replacer (config-time only).
	if fn := h.env().Replace; fn != nil {
		return fn(input, empty)
	}
	return input
}

func (h hostImpl) RequestGetVar(ctx context.Context, self uint32, key string) *string {
	scope := scopeFrom(ctx)
	// Prefer request-scoped getter (reads caddyhttp vars from r.Context()).
	if scope != nil && scope.GetVar != nil {
		v, ok := scope.GetVar(key)
		if !ok {
			return nil
		}
		s := fmt.Sprintf("%v", v)
		return &s
	}
	// Fallback to env-level getter.
	fn := h.env().GetVar
	if fn == nil {
		return nil
	}
	v, ok := fn(key)
	if !ok {
		return nil
	}
	return &v
}

func (h hostImpl) RequestSetVar(ctx context.Context, self uint32, key string, value string) {
	scope := scopeFrom(ctx)
	if scope != nil && scope.SetVar != nil {
		scope.SetVar(key, value)
		return
	}
	h.debugLog("caddywit: set-var: no scope setter available", zap.String("key", key))
}

func (h hostImpl) RequestResourceDrop(ctx context.Context, handle uint32) {
	// Request handles are host-owned, fixed per call; nothing to release.
}

// --- http-types: response-writer ---

func (h hostImpl) ResponseWriterSetHeader(ctx context.Context, self uint32, name string, value string) {
	if w := h.responseWriter(ctx); w != nil {
		w.Header().Set(name, value)
	}
}

func (h hostImpl) ResponseWriterAddHeader(ctx context.Context, self uint32, name string, value string) {
	if w := h.responseWriter(ctx); w != nil {
		w.Header().Add(name, value)
	}
}

func (h hostImpl) ResponseWriterRemoveHeader(ctx context.Context, self uint32, name string) {
	if w := h.responseWriter(ctx); w != nil {
		w.Header().Del(name)
	}
}

func (h hostImpl) ResponseWriterWriteStatus(ctx context.Context, self uint32, status uint16) {
	if w := h.responseWriter(ctx); w != nil {
		w.WriteHeader(int(status))
	}
}

func (h hostImpl) ResponseWriterWrite(ctx context.Context, self uint32, data []byte) (uint64, error) {
	w := h.responseWriter(ctx)
	if w == nil {
		return 0, errNoResponseWriter
	}
	n, err := w.Write(data)
	if n < 0 {
		n = 0
	}
	return uint64(n), err
}

func (h hostImpl) ResponseWriterFlush(ctx context.Context, self uint32) {
	if w := h.responseWriter(ctx); w != nil {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func (h hostImpl) ResponseWriterResourceDrop(ctx context.Context, handle uint32) {
	// Response-writer handles are host-owned, fixed per call; nothing to
	// release.
}

// --- http-types: next ---

func (h hostImpl) Next(ctx context.Context, req uint32, resp uint32) *gen.PluginError {
	s := h.scope(ctx)
	if s == nil || s.Next == nil {
		return &gen.PluginError{Message: "no next handler"}
	}
	err := s.Next(s.W, s.R)
	if err == nil {
		return nil
	}
	var pe *PluginError
	if errors.As(err, &pe) {
		return pluginErrorToGen(pe)
	}
	return &gen.PluginError{Message: err.Error()}
}

// --- http-types: next-buffered / buffered-response ---

// bufferedResponse is the host-side value behind one buffered-response
// handle: a snapshot of what the downstream chain wrote.
type bufferedResponse struct {
	status  uint16
	headers []abi.Pair[string, string]
	body    []byte
}

// errBufferedResponseTooLarge is returned to downstream writers once the
// recording cap is hit, so the downstream handler aborts instead of
// producing a silently-truncated response.
var errBufferedResponseTooLarge = errors.New("caddywit: buffered response exceeds size cap")

// bufferedRecorder is a minimal buffering http.ResponseWriter used by
// next-buffered. It records status/headers/body in memory; nothing reaches
// the client. Writes beyond limit fail with errBufferedResponseTooLarge.
type bufferedRecorder struct {
	header      http.Header
	status      int
	wroteHeader bool
	body        bytes.Buffer
	limit       int
	overflowed  bool
}

func newBufferedRecorder(limit int) *bufferedRecorder {
	return &bufferedRecorder{header: make(http.Header), limit: limit}
}

func (r *bufferedRecorder) Header() http.Header { return r.header }

func (r *bufferedRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
}

func (r *bufferedRecorder) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	if r.body.Len()+len(p) > r.limit {
		r.overflowed = true
		return 0, errBufferedResponseTooLarge
	}
	return r.body.Write(p)
}

// snapshot freezes the recording into a bufferedResponse.
func (r *bufferedRecorder) snapshot() *bufferedResponse {
	status := r.status
	if !r.wroteHeader {
		status = http.StatusOK
	}
	return &bufferedResponse{
		status:  uint16(status),
		headers: headerToPairs(r.header),
		body:    bytes.Clone(r.body.Bytes()),
	}
}

// headerToPairs flattens an http.Header into wire header pairs.
func headerToPairs(hdr http.Header) []abi.Pair[string, string] {
	pairs := make([]abi.Pair[string, string], 0, len(hdr))
	for name, values := range hdr {
		for _, v := range values {
			pairs = append(pairs, abi.Pair[string, string]{V0: name, V1: v})
		}
	}
	return pairs
}

func (h hostImpl) NextBuffered(ctx context.Context, req uint32) (uint32, *gen.PluginError) {
	st := scopeStateFrom(ctx)
	if st == nil || st.scope == nil || st.scope.Next == nil {
		return 0, &gen.PluginError{Message: "no next handler"}
	}
	rec := newBufferedRecorder(maxBufferedResponseBytes)
	if err := st.scope.Next(rec, st.scope.R); err != nil {
		var pe *PluginError
		if errors.As(err, &pe) {
			return 0, pluginErrorToGen(pe)
		}
		return 0, &gen.PluginError{Message: err.Error()}
	}
	if rec.overflowed {
		// The downstream handler swallowed the write error; refuse to hand
		// the guest a truncated body.
		return 0, &gen.PluginError{Message: errBufferedResponseTooLarge.Error()}
	}
	return st.mintBuffered(rec.snapshot()), nil
}

// buffered resolves a buffered-response handle from the current scope, or
// nil (logged at debug) when the handle or scope is unknown.
func (h hostImpl) buffered(ctx context.Context, self uint32) *bufferedResponse {
	st := scopeStateFrom(ctx)
	if st == nil {
		h.debugLog("caddywit: buffered-response host call outside request scope")
		return nil
	}
	br := st.buffered[self]
	if br == nil {
		h.debugLog("caddywit: unknown buffered-response handle", zap.Uint32("handle", self))
	}
	return br
}

func (h hostImpl) BufferedResponseStatus(ctx context.Context, self uint32) uint16 {
	if br := h.buffered(ctx, self); br != nil {
		return br.status
	}
	return 0
}

func (h hostImpl) BufferedResponseHeaders(ctx context.Context, self uint32) []abi.Pair[string, string] {
	if br := h.buffered(ctx, self); br != nil {
		return br.headers
	}
	return nil
}

func (h hostImpl) BufferedResponseBody(ctx context.Context, self uint32) []byte {
	if br := h.buffered(ctx, self); br != nil {
		return br.body
	}
	return nil
}

func (h hostImpl) BufferedResponseResourceDrop(ctx context.Context, handle uint32) {
	if st := scopeStateFrom(ctx); st != nil {
		delete(st.buffered, handle)
	}
}

// --- host-http ---

func (h hostImpl) HTTPSend(ctx context.Context, method string, url string, headers []abi.Pair[string, string], body []byte, options *gen.HTTPRequestOptions) (gen.HTTPResponse, error) {
	env := h.env()
	if !env.Permissions.HTTP {
		return gen.HTTPResponse{}, errHTTPPermission
	}
	client := env.HTTPClient
	if client == nil {
		client = defaultHTTPClient
	}
	maxBytes := uint64(defaultMaxResponseBytes)
	if options != nil {
		if options.MaxResponseBytes != nil {
			maxBytes = *options.MaxResponseBytes
		}
		if options.TimeoutMS != nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(*options.TimeoutMS)*time.Millisecond)
			defer cancel()
		}
		if options.FollowRedirects != nil && !*options.FollowRedirects {
			c := *client
			c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			client = &c
		}
	}
	if maxBytes > math.MaxInt64-1 {
		maxBytes = math.MaxInt64 - 1
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return gen.HTTPResponse{}, err
	}
	for _, p := range headers {
		req.Header.Add(p.V0, p.V1)
	}
	resp, err := client.Do(req)
	if err != nil {
		return gen.HTTPResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Read one byte past the cap so overflow is an error, not truncation.
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)+1))
	if err != nil {
		return gen.HTTPResponse{}, err
	}
	if uint64(len(data)) > maxBytes {
		return gen.HTTPResponse{}, fmt.Errorf("response body exceeds %d bytes", maxBytes)
	}
	return gen.HTTPResponse{
		Status:  uint16(resp.StatusCode),
		Headers: headerToPairs(resp.Header),
		Body:    data,
	}, nil
}

// --- host-tcp ---

func (h hostImpl) TCPConnect(ctx context.Context, address string, timeoutMS *uint32) (uint32, error) {
	env := h.env()
	if !env.Permissions.TCP {
		return 0, errTCPPermission
	}
	timeout := defaultNetTimeout
	if timeoutMS != nil {
		timeout = time.Duration(*timeoutMS) * time.Millisecond
	}
	var (
		conn net.Conn
		err  error
	)
	if env.DialTCP != nil {
		conn, err = env.DialTCP(ctx, address, timeout)
	} else {
		d := net.Dialer{Timeout: timeout}
		conn, err = d.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return 0, err
	}
	return h.m.storeConn(conn), nil
}

func (h hostImpl) TCPRead(ctx context.Context, self uint32, max uint64) (abi.Pair[[]byte, bool], error) {
	if !h.env().Permissions.TCP {
		return abi.Pair[[]byte, bool]{}, errTCPPermission
	}
	conn := h.m.conn(self)
	if conn == nil {
		return abi.Pair[[]byte, bool]{}, errUnknownTCPConn
	}
	n := max
	if n > maxTCPReadChunk {
		n = maxTCPReadChunk
	}
	buf := make([]byte, n)
	read, err := conn.Read(buf)
	switch {
	case err == nil:
		return abi.Pair[[]byte, bool]{V0: buf[:read], V1: false}, nil
	case errors.Is(err, io.EOF):
		return abi.Pair[[]byte, bool]{V0: buf[:read], V1: true}, nil
	default:
		return abi.Pair[[]byte, bool]{}, err
	}
}

func (h hostImpl) TCPWrite(ctx context.Context, self uint32, data []byte) (uint64, error) {
	if !h.env().Permissions.TCP {
		return 0, errTCPPermission
	}
	conn := h.m.conn(self)
	if conn == nil {
		return 0, errUnknownTCPConn
	}
	n, err := conn.Write(data)
	if n < 0 {
		n = 0
	}
	return uint64(n), err
}

func (h hostImpl) TCPSetDeadlineMS(ctx context.Context, self uint32, ms uint32) {
	conn := h.m.conn(self)
	if conn == nil {
		h.debugLog("caddywit: set-deadline-ms on unknown tcp connection", zap.Uint32("handle", self))
		return
	}
	deadline := time.Time{} // ms == 0 clears the deadline
	if ms > 0 {
		deadline = time.Now().Add(time.Duration(ms) * time.Millisecond)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		h.debugLog("caddywit: set-deadline-ms failed", zap.Error(err))
	}
}

func (h hostImpl) TCPClose(ctx context.Context, self uint32) {
	// Idempotent: closing an unknown/already-closed handle is a no-op.
	if conn := h.m.removeConn(self); conn != nil {
		_ = conn.Close()
	}
}

func (h hostImpl) TCPResourceDrop(ctx context.Context, handle uint32) {
	// Dropping the resource closes the connection if still open.
	if conn := h.m.removeConn(handle); conn != nil {
		_ = conn.Close()
	}
}
