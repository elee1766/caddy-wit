package gen

// host.go declares the Host interface: one method per function imported by
// the guest from the host side of caddy:plugin@0.1.0, plus the resource-drop
// hooks for the host-owned http-types resources. The embedding runtime binds
// a Host to the context before every entry into guest code (WithHost); the
// glue in instantiate.go resolves it back with HostFromContext.

import (
	"context"

	"github.com/elee1766/caddy-wit/pkg/abi"
)

// Host is the host side of the caddy:plugin import interfaces. Methods must
// never panic; Go errors returned from result-typed functions are delivered
// to the guest as the err case of the WIT result.
type Host interface {
	// caddy:plugin/log@0.1.0
	Log(ctx context.Context, lvl Level, msg string, fields []abi.Pair[string, string])

	// caddy:plugin/replacer@0.1.0
	ReplaceAll(ctx context.Context, input string, empty string) string
	Get(ctx context.Context, key string) *string

	// caddy:plugin/host-storage@0.1.0
	Store(ctx context.Context, key string, value []byte) error
	Load(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) bool
	ListKeys(ctx context.Context, prefix string, recursive bool) ([]string, error)
	Stat(ctx context.Context, key string) (KeyInfo, error)
	Lock(ctx context.Context, name string) error
	Unlock(ctx context.Context, name string) error

	// caddy:plugin/host-events@0.1.0
	Emit(ctx context.Context, name string, data string) error

	// caddy:plugin/http-types@0.1.0: request methods.
	RequestMethod(ctx context.Context, self uint32) string
	RequestURI(ctx context.Context, self uint32) string
	RequestPath(ctx context.Context, self uint32) string
	RequestQuery(ctx context.Context, self uint32) string
	RequestProtocol(ctx context.Context, self uint32) string
	RequestHost(ctx context.Context, self uint32) string
	RequestRemoteAddr(ctx context.Context, self uint32) string
	RequestHeaders(ctx context.Context, self uint32) []abi.Pair[string, string]
	RequestHeader(ctx context.Context, self uint32, name string) []string
	RequestSetHeader(ctx context.Context, self uint32, name string, value string)
	RequestAddHeader(ctx context.Context, self uint32, name string, value string)
	RequestRemoveHeader(ctx context.Context, self uint32, name string)
	RequestSetURI(ctx context.Context, self uint32, uri string)
	RequestSetMethod(ctx context.Context, self uint32, method string)
	RequestReadBody(ctx context.Context, self uint32, max uint64) (abi.Pair[[]byte, bool], error)
	RequestReplace(ctx context.Context, self uint32, input string, empty string) string
	RequestGetVar(ctx context.Context, self uint32, key string) *string
	RequestSetVar(ctx context.Context, self uint32, key string, value string)
	RequestResourceDrop(ctx context.Context, handle uint32)

	// caddy:plugin/http-types@0.1.0: response-writer methods.
	ResponseWriterSetHeader(ctx context.Context, self uint32, name string, value string)
	ResponseWriterAddHeader(ctx context.Context, self uint32, name string, value string)
	ResponseWriterRemoveHeader(ctx context.Context, self uint32, name string)
	ResponseWriterWriteStatus(ctx context.Context, self uint32, status uint16)
	ResponseWriterWrite(ctx context.Context, self uint32, data []byte) (uint64, error)
	ResponseWriterFlush(ctx context.Context, self uint32)
	ResponseWriterResourceDrop(ctx context.Context, handle uint32)

	// caddy:plugin/http-types@0.1.0: buffered-response methods. Handles are
	// host-minted by NextBuffered; unknown handles yield zero values.
	BufferedResponseStatus(ctx context.Context, self uint32) uint16
	BufferedResponseHeaders(ctx context.Context, self uint32) []abi.Pair[string, string]
	BufferedResponseBody(ctx context.Context, self uint32) []byte
	BufferedResponseResourceDrop(ctx context.Context, handle uint32)

	// caddy:plugin/http-types@0.1.0: next. A nil return means success; a
	// non-nil *PluginError is delivered to the guest as the err case.
	Next(ctx context.Context, req uint32, resp uint32) *PluginError

	// caddy:plugin/http-types@0.1.0: next-buffered. On success it returns a
	// host-minted own<buffered-response> handle; a non-nil *PluginError is
	// delivered to the guest as the err case.
	NextBuffered(ctx context.Context, req uint32) (uint32, *PluginError)

	// caddy:plugin/host-kv@0.1.0
	KVGet(ctx context.Context, key string) []byte
	KVSet(ctx context.Context, key string, value []byte, ttlMS *uint64)
	KVDelete(ctx context.Context, key string)
	KVIncrement(ctx context.Context, key string, delta int64, ttlMS *uint64) int64
	KVExists(ctx context.Context, key string) bool

	// caddy:plugin/host-http@0.1.0: send. A Go error is delivered to the
	// guest as the err(string) case (including permission denials).
	HTTPSend(ctx context.Context, method string, url string, headers []abi.Pair[string, string], body []byte, options *HTTPRequestOptions) (HTTPResponse, error)

	// caddy:plugin/host-tcp@0.1.0: connection resource. Handles are
	// host-minted by TCPConnect; a Go error from result-typed methods is
	// delivered to the guest as the err(string) case. Close and
	// ResourceDrop are idempotent (unknown handles are no-ops).
	TCPConnect(ctx context.Context, address string, timeoutMS *uint32) (uint32, error)
	TCPRead(ctx context.Context, self uint32, max uint64) (abi.Pair[[]byte, bool], error)
	TCPWrite(ctx context.Context, self uint32, data []byte) (uint64, error)
	TCPSetDeadlineMS(ctx context.Context, self uint32, ms uint32)
	TCPClose(ctx context.Context, self uint32)
	TCPResourceDrop(ctx context.Context, handle uint32)
}

// hostCtxKey is the private context key carrying the Host implementation.
type hostCtxKey struct{}

// WithHost attaches h to ctx. Every entry into guest code must run with a
// Host attached, or host imports degrade to no-ops / "host not available"
// errors.
func WithHost(ctx context.Context, h Host) context.Context {
	return context.WithValue(ctx, hostCtxKey{}, h)
}

// HostFromContext returns the Host attached to ctx, or nil.
func HostFromContext(ctx context.Context) Host {
	h, _ := ctx.Value(hostCtxKey{}).(Host)
	return h
}
