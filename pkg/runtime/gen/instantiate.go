package gen

// instantiate.go registers every host module the caddy:plugin@0.1.0 guest
// imports:
//
//   - the host capability interfaces (log, replacer, host-storage,
//     host-events, http-types), dispatched to the Host attached to the call
//     context, and
//   - the canonical-ABI builtins for guest-exported resources
//     ("[export]caddy:plugin/lifecycle@0.1.0" and ".../fs@0.1.0"), backed by
//     the abi.ResourceTables attached to the call context.
//
// Missing Host on the context degrades gracefully: void functions no-op,
// result-typed functions deliver an err("host not available") to the guest,
// and value-typed functions return zero values. Missing resource tables trap
// for resource-new/rep (there is no correct answer to fabricate) and no-op
// for resource-drop.

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"

	"github.com/elee1766/caddy-wit/pkg/abi"
)

const errHostUnavailable = "host not available"

// Instantiate registers all caddy:plugin host modules on rt. It must be
// called exactly once per wazero runtime, before instantiating any guest.
func Instantiate(ctx context.Context, rt wazero.Runtime) error {
	for _, m := range []struct {
		name string
		fns  []hostFunc
	}{
		{"caddy:plugin/log@0.1.0", logFuncs()},
		{"caddy:plugin/replacer@0.1.0", replacerFuncs()},
		{"caddy:plugin/host-storage@0.1.0", hostStorageFuncs()},
		{"caddy:plugin/host-events@0.1.0", hostEventsFuncs()},
		{"caddy:plugin/host-kv@0.1.0", hostKVFuncs()},
		{"caddy:plugin/host-http@0.1.0", hostHTTPFuncs()},
		{"caddy:plugin/host-tcp@0.1.0", hostTCPFuncs()},
		{"caddy:plugin/http-types@0.1.0", httpTypesFuncs()},
		{"[export]caddy:plugin/lifecycle@0.1.0", resourceBuiltinFuncs(
			"instance", "lifecycle#instance", ExportPrefixLifecycle+"[dtor]instance")},
		{"[export]caddy:plugin/fs@0.1.0", resourceBuiltinFuncs(
			"file", "fs#file", ExportPrefixFS+"[dtor]file")},
	} {
		if err := instantiateHostModule(ctx, rt, m.name, m.fns); err != nil {
			return err
		}
	}
	return nil
}

// hostFunc is one exported field of a host module.
type hostFunc struct {
	name string
	ft   *abi.FuncType
	impl abi.HostImpl
}

func instantiateHostModule(ctx context.Context, rt wazero.Runtime, module string, fns []hostFunc) error {
	b := rt.NewHostModuleBuilder(module)
	for _, f := range fns {
		goFn, params, results := abi.NewHostFunc(module+"#"+f.name, f.ft, f.impl)
		b = b.NewFunctionBuilder().
			WithGoModuleFunction(goFn, params, results).
			Export(f.name)
	}
	if _, err := b.Instantiate(ctx); err != nil {
		return fmt.Errorf("gen: instantiating host module %q: %w", module, err)
	}
	return nil
}

// errRes wraps a host-side Go error as the err(string) case for the guest.
func errRes(err error) abi.Res { return abi.ErrVal(err.Error()) }

var errNoHost = abi.ErrVal(errHostUnavailable)

// --- caddy:plugin/log@0.1.0 ---

func logFuncs() []hostFunc {
	return []hostFunc{
		{"log", ftLogLog, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			h := HostFromContext(ctx)
			if h == nil {
				return nil, nil
			}
			lvl, err := asU32(args[0], "log.lvl")
			if err != nil {
				return nil, err
			}
			msg, err := asString(args[1], "log.msg")
			if err != nil {
				return nil, err
			}
			fields, err := pairsFromAny(args[2], "log.fields")
			if err != nil {
				return nil, err
			}
			h.Log(ctx, Level(lvl), msg, fields)
			return nil, nil
		}},
	}
}

// --- caddy:plugin/replacer@0.1.0 ---

func replacerFuncs() []hostFunc {
	return []hostFunc{
		{"replace-all", ftReplacerReplaceAll, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			input, err := asString(args[0], "replace-all.input")
			if err != nil {
				return nil, err
			}
			empty, err := asString(args[1], "replace-all.empty")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return input, nil
			}
			return h.ReplaceAll(ctx, input, empty), nil
		}},
		{"get", ftReplacerGet, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			key, err := asString(args[0], "get.key")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return abi.None, nil
			}
			return optStringToAny(h.Get(ctx, key)), nil
		}},
	}
}

// --- caddy:plugin/host-storage@0.1.0 ---

func hostStorageFuncs() []hostFunc {
	return []hostFunc{
		{"store", ftHostStorageStore, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			key, err := asString(args[0], "store.key")
			if err != nil {
				return nil, err
			}
			value, err := asBytes(args[1], "store.value")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			if serr := h.Store(ctx, key, value); serr != nil {
				return errRes(serr), nil
			}
			return abi.OkVal(nil), nil
		}},
		{"load", ftHostStorageLoad, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			key, err := asString(args[0], "load.key")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			data, lerr := h.Load(ctx, key)
			if lerr != nil {
				return errRes(lerr), nil
			}
			if data == nil {
				data = []byte{}
			}
			return abi.OkVal(data), nil
		}},
		{"delete", ftHostStorageDelete, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			key, err := asString(args[0], "delete.key")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			if derr := h.Delete(ctx, key); derr != nil {
				return errRes(derr), nil
			}
			return abi.OkVal(nil), nil
		}},
		{"exists", ftHostStorageExists, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			key, err := asString(args[0], "exists.key")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return false, nil
			}
			return h.Exists(ctx, key), nil
		}},
		{"list-keys", ftHostStorageListKeys, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			prefix, err := asString(args[0], "list-keys.prefix")
			if err != nil {
				return nil, err
			}
			recursive, err := asBool(args[1], "list-keys.recursive")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			keys, lerr := h.ListKeys(ctx, prefix, recursive)
			if lerr != nil {
				return errRes(lerr), nil
			}
			return abi.OkVal(stringsToAny(keys)), nil
		}},
		{"stat", ftHostStorageStat, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			key, err := asString(args[0], "stat.key")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			ki, serr := h.Stat(ctx, key)
			if serr != nil {
				return errRes(serr), nil
			}
			return abi.OkVal(keyInfoToAny(ki)), nil
		}},
		{"lock", ftHostStorageLock, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			name, err := asString(args[0], "lock.name")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			if lerr := h.Lock(ctx, name); lerr != nil {
				return errRes(lerr), nil
			}
			return abi.OkVal(nil), nil
		}},
		{"unlock", ftHostStorageUnlock, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			name, err := asString(args[0], "unlock.name")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			if uerr := h.Unlock(ctx, name); uerr != nil {
				return errRes(uerr), nil
			}
			return abi.OkVal(nil), nil
		}},
	}
}

// --- caddy:plugin/host-events@0.1.0 ---

func hostEventsFuncs() []hostFunc {
	return []hostFunc{
		{"emit", ftHostEventsEmit, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			name, err := asString(args[0], "emit.name")
			if err != nil {
				return nil, err
			}
			data, err := asString(args[1], "emit.data")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			if eerr := h.Emit(ctx, name, data); eerr != nil {
				return errRes(eerr), nil
			}
			return abi.OkVal(nil), nil
		}},
	}
}

// --- caddy:plugin/host-kv@0.1.0 ---

func hostKVFuncs() []hostFunc {
	return []hostFunc{
		{"get", ftKVGet, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			key, err := asString(args[0], "kv.get.key")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return abi.None, nil
			}
			data := h.KVGet(ctx, key)
			if data == nil {
				return abi.None, nil
			}
			return abi.SomeVal(data), nil
		}},
		{"set", ftKVSet, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			key, err := asString(args[0], "kv.set.key")
			if err != nil {
				return nil, err
			}
			value, err := asBytes(args[1], "kv.set.value")
			if err != nil {
				return nil, err
			}
			ttl, err := optFromAny[uint64](args[2], "kv.set.ttl-ms")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.KVSet(ctx, key, value, ttl)
			}
			return nil, nil
		}},
		{"delete", ftKVDelete, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			key, err := asString(args[0], "kv.delete.key")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.KVDelete(ctx, key)
			}
			return nil, nil
		}},
		{"increment", ftKVIncrement, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			key, err := asString(args[0], "kv.increment.key")
			if err != nil {
				return nil, err
			}
			delta, err := asS64(args[1], "kv.increment.delta")
			if err != nil {
				return nil, err
			}
			ttl, err := optFromAny[uint64](args[2], "kv.increment.ttl-ms")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return delta, nil
			}
			return h.KVIncrement(ctx, key, delta, ttl), nil
		}},
		{"exists", ftKVExists, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			key, err := asString(args[0], "kv.exists.key")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return false, nil
			}
			return h.KVExists(ctx, key), nil
		}},
	}
}

// --- caddy:plugin/host-http@0.1.0 ---

func hostHTTPFuncs() []hostFunc {
	return []hostFunc{
		{"send", ftHostHTTPSend, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			method, err := asString(args[0], "send.method")
			if err != nil {
				return nil, err
			}
			url, err := asString(args[1], "send.url")
			if err != nil {
				return nil, err
			}
			headers, err := pairsFromAny(args[2], "send.headers")
			if err != nil {
				return nil, err
			}
			body, err := asBytes(args[3], "send.body")
			if err != nil {
				return nil, err
			}
			options, err := httpRequestOptionsFromAny(args[4], "send.options")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			resp, serr := h.HTTPSend(ctx, method, url, headers, body, options)
			if serr != nil {
				return errRes(serr), nil
			}
			return abi.OkVal(httpResponseToAny(resp)), nil
		}},
	}
}

// --- caddy:plugin/host-tcp@0.1.0 ---

func hostTCPFuncs() []hostFunc {
	return []hostFunc{
		{"[static]connection.connect", ftTCPConnConnect, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			address, err := asString(args[0], "connection.connect.address")
			if err != nil {
				return nil, err
			}
			timeoutMS, err := optFromAny[uint32](args[1], "connection.connect.timeout-ms")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			handle, cerr := h.TCPConnect(ctx, address, timeoutMS)
			if cerr != nil {
				return errRes(cerr), nil
			}
			return abi.OkVal(handle), nil
		}},
		{"[method]connection.read", ftTCPConnRead, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "connection.read.self")
			if err != nil {
				return nil, err
			}
			max, err := asU64(args[1], "connection.read.max")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			pair, rerr := h.TCPRead(ctx, self, max)
			if rerr != nil {
				return errRes(rerr), nil
			}
			data := pair.V0
			if data == nil {
				data = []byte{}
			}
			return abi.OkVal([]any{data, pair.V1}), nil
		}},
		{"[method]connection.write", ftTCPConnWrite, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "connection.write.self")
			if err != nil {
				return nil, err
			}
			data, err := asBytes(args[1], "connection.write.data")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			n, werr := h.TCPWrite(ctx, self, data)
			if werr != nil {
				return errRes(werr), nil
			}
			return abi.OkVal(n), nil
		}},
		{"[method]connection.set-deadline-ms", ftTCPConnSetDeadlineMS, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "connection.set-deadline-ms.self")
			if err != nil {
				return nil, err
			}
			ms, err := asU32(args[1], "connection.set-deadline-ms.ms")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.TCPSetDeadlineMS(ctx, self, ms)
			}
			return nil, nil
		}},
		{"[method]connection.close", ftTCPConnClose, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "connection.close.self")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.TCPClose(ctx, self)
			}
			return nil, nil
		}},
		{"[resource-drop]connection", ftResourceDrop, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			handle, err := asU32(args[0], "[resource-drop]connection.handle")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.TCPResourceDrop(ctx, handle)
			}
			return nil, nil
		}},
	}
}

// --- caddy:plugin/http-types@0.1.0 ---

// requestGetter builds a (self) -> string request accessor.
func requestGetter(what string, get func(Host, context.Context, uint32) string) abi.HostImpl {
	return func(ctx context.Context, _ api.Module, args []any) (any, error) {
		self, err := asU32(args[0], what+".self")
		if err != nil {
			return nil, err
		}
		h := HostFromContext(ctx)
		if h == nil {
			return "", nil
		}
		return get(h, ctx, self), nil
	}
}

// requestNameValue builds a (self, name, value) -> none setter.
func requestNameValue(what string, set func(Host, context.Context, uint32, string, string)) abi.HostImpl {
	return func(ctx context.Context, _ api.Module, args []any) (any, error) {
		self, err := asU32(args[0], what+".self")
		if err != nil {
			return nil, err
		}
		name, err := asString(args[1], what+".name")
		if err != nil {
			return nil, err
		}
		value, err := asString(args[2], what+".value")
		if err != nil {
			return nil, err
		}
		if h := HostFromContext(ctx); h != nil {
			set(h, ctx, self, name, value)
		}
		return nil, nil
	}
}

func httpTypesFuncs() []hostFunc {
	return []hostFunc{
		// request: string accessors.
		{"[method]request.method", ftRequestGetString, requestGetter("request.method", Host.RequestMethod)},
		{"[method]request.uri", ftRequestGetString, requestGetter("request.uri", Host.RequestURI)},
		{"[method]request.path", ftRequestGetString, requestGetter("request.path", Host.RequestPath)},
		{"[method]request.query", ftRequestGetString, requestGetter("request.query", Host.RequestQuery)},
		{"[method]request.protocol", ftRequestGetString, requestGetter("request.protocol", Host.RequestProtocol)},
		{"[method]request.host", ftRequestGetString, requestGetter("request.host", Host.RequestHost)},
		{"[method]request.remote-addr", ftRequestGetString, requestGetter("request.remote-addr", Host.RequestRemoteAddr)},

		{"[method]request.headers", ftRequestHeaders, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "request.headers.self")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return []any{}, nil
			}
			return pairsToAny(h.RequestHeaders(ctx, self)), nil
		}},
		{"[method]request.header", ftRequestHeader, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "request.header.self")
			if err != nil {
				return nil, err
			}
			name, err := asString(args[1], "request.header.name")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return []any{}, nil
			}
			return stringsToAny(h.RequestHeader(ctx, self, name)), nil
		}},
		{"[method]request.set-header", ftRequestSetHeader, requestNameValue("request.set-header", Host.RequestSetHeader)},
		{"[method]request.add-header", ftRequestSetHeader, requestNameValue("request.add-header", Host.RequestAddHeader)},
		{"[method]request.remove-header", ftRequestRemoveHeader, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "request.remove-header.self")
			if err != nil {
				return nil, err
			}
			name, err := asString(args[1], "request.remove-header.name")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.RequestRemoveHeader(ctx, self, name)
			}
			return nil, nil
		}},
		{"[method]request.set-uri", ftRequestSetString, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "request.set-uri.self")
			if err != nil {
				return nil, err
			}
			uri, err := asString(args[1], "request.set-uri.uri")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.RequestSetURI(ctx, self, uri)
			}
			return nil, nil
		}},
		{"[method]request.set-method", ftRequestSetString, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "request.set-method.self")
			if err != nil {
				return nil, err
			}
			method, err := asString(args[1], "request.set-method.method")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.RequestSetMethod(ctx, self, method)
			}
			return nil, nil
		}},
		{"[method]request.read-body", ftRequestReadBody, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "request.read-body.self")
			if err != nil {
				return nil, err
			}
			max, err := asU64(args[1], "request.read-body.max")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			pair, rerr := h.RequestReadBody(ctx, self, max)
			if rerr != nil {
				return errRes(rerr), nil
			}
			body := pair.V0
			if body == nil {
				body = []byte{}
			}
			return abi.OkVal([]any{body, pair.V1}), nil
		}},
		{"[method]request.replace", ftRequestReplace, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "request.replace.self")
			if err != nil {
				return nil, err
			}
			input, err := asString(args[1], "request.replace.input")
			if err != nil {
				return nil, err
			}
			empty, err := asString(args[2], "request.replace.empty")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return input, nil
			}
			return h.RequestReplace(ctx, self, input, empty), nil
		}},
		{"[method]request.get-var", ftRequestGetVar, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "request.get-var.self")
			if err != nil {
				return nil, err
			}
			key, err := asString(args[1], "request.get-var.key")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return abi.None, nil
			}
			return optStringToAny(h.RequestGetVar(ctx, self, key)), nil
		}},
		{"[method]request.set-var", ftRequestSetVar, requestNameValue("request.set-var", func(h Host, ctx context.Context, self uint32, key, value string) {
			h.RequestSetVar(ctx, self, key, value)
		})},

		// response-writer.
		{"[method]response-writer.set-header", ftRespSetHeader, requestNameValue("response-writer.set-header", Host.ResponseWriterSetHeader)},
		{"[method]response-writer.add-header", ftRespSetHeader, requestNameValue("response-writer.add-header", Host.ResponseWriterAddHeader)},
		{"[method]response-writer.remove-header", ftRespRemoveHeader, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "response-writer.remove-header.self")
			if err != nil {
				return nil, err
			}
			name, err := asString(args[1], "response-writer.remove-header.name")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.ResponseWriterRemoveHeader(ctx, self, name)
			}
			return nil, nil
		}},
		{"[method]response-writer.write-status", ftRespWriteStatus, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "response-writer.write-status.self")
			if err != nil {
				return nil, err
			}
			status, ok := args[1].(uint16)
			if !ok {
				return nil, fmt.Errorf("gen: response-writer.write-status.status: expected uint16, got %T", args[1])
			}
			if h := HostFromContext(ctx); h != nil {
				h.ResponseWriterWriteStatus(ctx, self, status)
			}
			return nil, nil
		}},
		{"[method]response-writer.write", ftRespWrite, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "response-writer.write.self")
			if err != nil {
				return nil, err
			}
			data, err := asBytes(args[1], "response-writer.write.data")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return errNoHost, nil
			}
			n, werr := h.ResponseWriterWrite(ctx, self, data)
			if werr != nil {
				return errRes(werr), nil
			}
			return abi.OkVal(n), nil
		}},
		{"[method]response-writer.flush", ftRespFlush, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "response-writer.flush.self")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.ResponseWriterFlush(ctx, self)
			}
			return nil, nil
		}},

		// buffered-response.
		{"[method]buffered-response.status", ftBufferedResponseStatus, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "buffered-response.status.self")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return uint16(0), nil
			}
			return h.BufferedResponseStatus(ctx, self), nil
		}},
		{"[method]buffered-response.headers", ftRequestHeaders, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "buffered-response.headers.self")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return []any{}, nil
			}
			return pairsToAny(h.BufferedResponseHeaders(ctx, self)), nil
		}},
		{"[method]buffered-response.body", ftBufferedResponseBody, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			self, err := asU32(args[0], "buffered-response.body.self")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return []byte{}, nil
			}
			body := h.BufferedResponseBody(ctx, self)
			if body == nil {
				body = []byte{}
			}
			return body, nil
		}},

		// next.
		{"next", ftHTTPNext, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			req, err := asU32(args[0], "next.req")
			if err != nil {
				return nil, err
			}
			resp, err := asU32(args[1], "next.resp")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return abi.ErrVal(pluginErrorToAny(PluginError{Message: errHostUnavailable})), nil
			}
			if pe := h.Next(ctx, req, resp); pe != nil {
				return abi.ErrVal(pluginErrorToAny(*pe)), nil
			}
			return abi.OkVal(nil), nil
		}},

		// next-buffered.
		{"next-buffered", ftHTTPNextBuffered, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			req, err := asU32(args[0], "next-buffered.req")
			if err != nil {
				return nil, err
			}
			h := HostFromContext(ctx)
			if h == nil {
				return abi.ErrVal(pluginErrorToAny(PluginError{Message: errHostUnavailable})), nil
			}
			handle, pe := h.NextBuffered(ctx, req)
			if pe != nil {
				return abi.ErrVal(pluginErrorToAny(*pe)), nil
			}
			return abi.OkVal(handle), nil
		}},

		// Host-owned resource drops.
		{"[resource-drop]request", ftResourceDrop, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			handle, err := asU32(args[0], "[resource-drop]request.handle")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.RequestResourceDrop(ctx, handle)
			}
			return nil, nil
		}},
		{"[resource-drop]response-writer", ftResourceDrop, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			handle, err := asU32(args[0], "[resource-drop]response-writer.handle")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.ResponseWriterResourceDrop(ctx, handle)
			}
			return nil, nil
		}},
		{"[resource-drop]buffered-response", ftResourceDrop, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			handle, err := asU32(args[0], "[resource-drop]buffered-response.handle")
			if err != nil {
				return nil, err
			}
			if h := HostFromContext(ctx); h != nil {
				h.BufferedResponseResourceDrop(ctx, handle)
			}
			return nil, nil
		}},
	}
}

// --- guest-exported-resource builtins ---

// resourceBuiltinFuncs builds the [resource-new]/[resource-rep]/
// [resource-drop] builtins the guest imports from
// "[export]caddy:plugin/<iface>@0.1.0" for one exported resource type.
// Handles live in the abi.ResourceTables attached to the call context under
// tableKey; drop invokes the guest's destructor export (if present) with the
// removed rep.
func resourceBuiltinFuncs(resource, tableKey, dtorExport string) []hostFunc {
	return []hostFunc{
		{"[resource-new]" + resource, ftResourceNew, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			rep, err := asU32(args[0], "[resource-new]"+resource+".rep")
			if err != nil {
				return nil, err
			}
			tables := abi.TablesFromContext(ctx)
			if tables == nil {
				return nil, fmt.Errorf("gen: [resource-new]%s: no resource tables on context", resource)
			}
			return tables.Table(tableKey).New(rep), nil
		}},
		{"[resource-rep]" + resource, ftResourceRep, func(ctx context.Context, _ api.Module, args []any) (any, error) {
			handle, err := asU32(args[0], "[resource-rep]"+resource+".handle")
			if err != nil {
				return nil, err
			}
			tables := abi.TablesFromContext(ctx)
			if tables == nil {
				return nil, fmt.Errorf("gen: [resource-rep]%s: no resource tables on context", resource)
			}
			rep, ok := tables.Table(tableKey).Rep(handle)
			if !ok {
				return nil, fmt.Errorf("gen: [resource-rep]%s: unknown handle %d", resource, handle)
			}
			return rep, nil
		}},
		{"[resource-drop]" + resource, ftResourceDrop, func(ctx context.Context, mod api.Module, args []any) (any, error) {
			handle, err := asU32(args[0], "[resource-drop]"+resource+".handle")
			if err != nil {
				return nil, err
			}
			tables := abi.TablesFromContext(ctx)
			if tables == nil {
				return nil, nil // nothing tracked; treat as already dropped
			}
			rep, ok := tables.Table(tableKey).Remove(handle)
			if !ok {
				return nil, nil // already dropped
			}
			// Some guests inline destructors instead of exporting [dtor];
			// a missing export is a no-op.
			dtor := mod.ExportedFunction(dtorExport)
			if dtor == nil {
				return nil, nil
			}
			if _, derr := dtor.Call(ctx, uint64(rep)); derr != nil {
				return nil, fmt.Errorf("gen: [resource-drop]%s: destructor: %w", resource, derr)
			}
			return nil, nil
		}},
	}
}
