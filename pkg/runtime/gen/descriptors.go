package gen

// descriptors.go declares the abi.Type descriptors for every WIT typedef in
// caddy:plugin@0.1.0 and the abi.FuncType tables for every function,
// following the resolved WIT model (field order and layout are asserted in
// descriptors_test.go against the wit-bindgen dump).

import "github.com/elee1766/caddy-wit/pkg/abi"

// Shared type descriptors.
var (
	// log.level: enum { debug, info, warn, error }
	levelT = abi.Enum(4)

	// list<tuple<string, string>> (log fields, request headers)
	stringPairListT = abi.List(abi.Record(abi.String, abi.String))

	// types.plugin-error: record { message: string, status: option<u16> }
	pluginErrorT = abi.Record(abi.String, abi.Option(abi.U16))

	// types.key-info: record { key: string, modified: s64, size: s64, terminal: bool }
	keyInfoT = abi.Record(abi.String, abi.S64, abi.S64, abi.Bool)

	// types.event: record { id: string, name: string, timestamp: s64, origin: string, data: json }
	eventT = abi.Record(abi.String, abi.String, abi.S64, abi.String, abi.String)

	// fs.file-info: record { name: string, size: u64, mode: u32, mod-time: s64, dir: bool }
	fileInfoT = abi.Record(abi.String, abi.U64, abi.U32, abi.S64, abi.Bool)

	// manifest.directive-position: enum { before, after }
	directivePositionT = abi.Enum(2)

	// manifest.caddyfile-order: record { position: directive-position, relative-to: string }
	caddyfileOrderT = abi.Record(directivePositionT, abi.String)

	// manifest.module-decl: record { id: string, docs: option<string>,
	// caddyfile-order: option<caddyfile-order> }
	moduleDeclT = abi.Record(abi.String, abi.Option(abi.String), abi.Option(caddyfileOrderT))

	// manifest.plugin-info: record { name: string, version: option<string>, modules: list<module-decl> }
	pluginInfoT = abi.Record(abi.String, abi.Option(abi.String), abi.List(moduleDeclT))

	// config.token: record { file: string, line: u32, text: string, quoted: bool }
	tokenT = abi.Record(abi.String, abi.U32, abi.String, abi.Bool)

	// tls-issuer.issued-certificate: record { certificate-pem: list<u8>, metadata: option<json> }
	issuedCertT = abi.Record(abi.List(abi.U8), abi.Option(abi.String))

	// tls-cert-loader.certificate-key-pair: record { certificate-pem: list<u8>, key-pem: list<u8>, tags: list<string> }
	certKeyPairT = abi.Record(abi.List(abi.U8), abi.List(abi.U8), abi.List(abi.String))

	// event-handler.handler-error: variant { aborted, message(string) }
	handlerErrorT = abi.Variant(nil, abi.String)

	// tuple<list<u8>, bool> (read-body / file.read / tcp read payload)
	bytesEOFT = abi.Record(abi.List(abi.U8), abi.Bool)

	// upstream-source.upstream: record { dial: string, max-requests: u32 }
	upstreamT = abi.Record(abi.String, abi.U32)

	// dns-provider.dns-record: record { rr-type: string, name: string,
	// value: string, ttl-seconds: u32, priority: option<u16> }
	dnsRecordT = abi.Record(abi.String, abi.String, abi.String, abi.U32, abi.Option(abi.U16))

	// host-http.request-options: record { timeout-ms: option<u32>,
	// max-response-bytes: option<u64>, follow-redirects: option<bool> }
	httpRequestOptionsT = abi.Record(abi.Option(abi.U32), abi.Option(abi.U64), abi.Option(abi.Bool))

	// host-http.response: record { status: u16,
	// headers: list<tuple<string, string>>, body: list<u8> }
	httpResponseT = abi.Record(abi.U16, stringPairListT, abi.List(abi.U8))

	// upstream-source result shape.
	resultUpstreamsStrT = abi.Result(abi.List(upstreamT), abi.String)

	// Common result shapes.
	resultVoidStrT     = abi.Result(nil, abi.String)
	resultVoidPerrT    = abi.Result(nil, pluginErrorT)
	resultBytesStrT    = abi.Result(abi.List(abi.U8), abi.String)
	resultStringsStrT  = abi.Result(abi.List(abi.String), abi.String)
	resultKeyInfoStrT  = abi.Result(keyInfoT, abi.String)
	resultBytesEOFStrT = abi.Result(bytesEOFT, abi.String)
	resultFileInfoStrT = abi.Result(fileInfoT, abi.String)
)

// Host import signatures (guest imports these from the host).
var (
	// log.log: func(lvl: level, msg: string, fields: list<tuple<string,string>>)
	ftLogLog = &abi.FuncType{Params: []abi.Type{levelT, abi.String, stringPairListT}}

	// replacer.replace-all: func(input: string, empty: string) -> string
	ftReplacerReplaceAll = &abi.FuncType{Params: []abi.Type{abi.String, abi.String}, Result: abi.String}
	// replacer.get: func(key: string) -> option<string>
	ftReplacerGet = &abi.FuncType{Params: []abi.Type{abi.String}, Result: abi.Option(abi.String)}

	// host-storage
	ftHostStorageStore    = &abi.FuncType{Params: []abi.Type{abi.String, abi.List(abi.U8)}, Result: resultVoidStrT}
	ftHostStorageLoad     = &abi.FuncType{Params: []abi.Type{abi.String}, Result: resultBytesStrT}
	ftHostStorageDelete   = &abi.FuncType{Params: []abi.Type{abi.String}, Result: resultVoidStrT}
	ftHostStorageExists   = &abi.FuncType{Params: []abi.Type{abi.String}, Result: abi.Bool}
	ftHostStorageListKeys = &abi.FuncType{Params: []abi.Type{abi.String, abi.Bool}, Result: resultStringsStrT}
	ftHostStorageStat     = &abi.FuncType{Params: []abi.Type{abi.String}, Result: resultKeyInfoStrT}
	ftHostStorageLock     = &abi.FuncType{Params: []abi.Type{abi.String}, Result: resultVoidStrT}
	ftHostStorageUnlock   = &abi.FuncType{Params: []abi.Type{abi.String}, Result: resultVoidStrT}

	// host-events.emit: func(name: string, data: json) -> result<_, string>
	ftHostEventsEmit = &abi.FuncType{Params: []abi.Type{abi.String, abi.String}, Result: resultVoidStrT}

	// http-types: request methods (self is a borrow handle).
	ftRequestGetString    = &abi.FuncType{Params: []abi.Type{abi.Handle}, Result: abi.String}
	ftRequestHeaders      = &abi.FuncType{Params: []abi.Type{abi.Handle}, Result: stringPairListT}
	ftRequestHeader       = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: abi.List(abi.String)}
	ftRequestSetHeader    = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String, abi.String}}
	ftRequestRemoveHeader = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}}
	ftRequestSetString    = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}}
	ftRequestReadBody     = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.U64}, Result: resultBytesEOFStrT}
	ftRequestReplace      = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String, abi.String}, Result: abi.String}
	ftRequestGetVar       = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: abi.Option(abi.String)}
	ftRequestSetVar       = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String, abi.String}}

	// http-types: response-writer methods.
	ftRespSetHeader    = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String, abi.String}}
	ftRespRemoveHeader = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}}
	ftRespWriteStatus  = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.U16}}
	ftRespWrite        = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.List(abi.U8)}, Result: abi.Result(abi.U64, abi.String)}
	ftRespFlush        = &abi.FuncType{Params: []abi.Type{abi.Handle}}

	// http-types: buffered-response methods.
	ftBufferedResponseStatus = &abi.FuncType{Params: []abi.Type{abi.Handle}, Result: abi.U16}
	ftBufferedResponseBody   = &abi.FuncType{Params: []abi.Type{abi.Handle}, Result: abi.List(abi.U8)}
	// buffered-response.headers reuses ftRequestHeaders: (self) -> list<tuple<string,string>>.

	// http-types.next: func(req: borrow<request>, resp: borrow<response-writer>) -> result<_, plugin-error>
	ftHTTPNext = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.Handle}, Result: resultVoidPerrT}

	// http-types.next-buffered: func(req: borrow<request>) -> result<own<buffered-response>, plugin-error>
	ftHTTPNextBuffered = &abi.FuncType{Params: []abi.Type{abi.Handle}, Result: abi.Result(abi.Handle, pluginErrorT)}

	// host-http.send: func(method: string, url: string,
	// headers: list<tuple<string,string>>, body: list<u8>,
	// options: option<request-options>) -> result<response, string>
	ftHostHTTPSend = &abi.FuncType{
		Params: []abi.Type{abi.String, abi.String, stringPairListT, abi.List(abi.U8), abi.Option(httpRequestOptionsT)},
		Result: abi.Result(httpResponseT, abi.String),
	}

	// host-tcp.[static]connection.connect: func(address: string,
	// timeout-ms: option<u32>) -> result<own<connection>, string>
	ftTCPConnConnect = &abi.FuncType{Params: []abi.Type{abi.String, abi.Option(abi.U32)}, Result: abi.Result(abi.Handle, abi.String)}
	// host-tcp.[method]connection.read: func(self, max: u64) -> result<tuple<list<u8>, bool>, string>
	ftTCPConnRead = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.U64}, Result: resultBytesEOFStrT}
	// host-tcp.[method]connection.write: func(self, data: list<u8>) -> result<u64, string>
	ftTCPConnWrite = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.List(abi.U8)}, Result: abi.Result(abi.U64, abi.String)}
	// host-tcp.[method]connection.set-deadline-ms: func(self, ms: u32)
	ftTCPConnSetDeadlineMS = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.U32}}
	// host-tcp.[method]connection.close: func(self)
	ftTCPConnClose = &abi.FuncType{Params: []abi.Type{abi.Handle}}

	// host-kv.get: func(key: string) -> option<list<u8>>
	ftKVGet = &abi.FuncType{Params: []abi.Type{abi.String}, Result: abi.Option(abi.List(abi.U8))}
	// host-kv.set: func(key: string, value: list<u8>, ttl-ms: option<u64>)
	ftKVSet = &abi.FuncType{Params: []abi.Type{abi.String, abi.List(abi.U8), abi.Option(abi.U64)}}
	// host-kv.delete: func(key: string)
	ftKVDelete = &abi.FuncType{Params: []abi.Type{abi.String}}
	// host-kv.increment: func(key: string, delta: s64, ttl-ms: option<u64>) -> s64
	ftKVIncrement = &abi.FuncType{Params: []abi.Type{abi.String, abi.S64, abi.Option(abi.U64)}, Result: abi.S64}
	// host-kv.exists: func(key: string) -> bool
	ftKVExists = &abi.FuncType{Params: []abi.Type{abi.String}, Result: abi.Bool}

	// [resource-drop]request / [resource-drop]response-writer: (i32) -> ()
	ftResourceDrop = &abi.FuncType{Params: []abi.Type{abi.Handle}}

	// Guest-exported-resource builtins imported from "[export]caddy:plugin/...".
	// [resource-new]: (i32 rep) -> i32 handle; [resource-rep]: (i32 handle) -> i32 rep.
	ftResourceNew = &abi.FuncType{Params: []abi.Type{abi.Handle}, Result: abi.Handle}
	ftResourceRep = &abi.FuncType{Params: []abi.Type{abi.Handle}, Result: abi.Handle}
)

// Guest export signatures.
var (
	// manifest.describe: func() -> plugin-info
	ftManifestDescribe = &abi.FuncType{Result: pluginInfoT}

	// lifecycle.[static]instance.provision: func(module-id: string, config: json) -> result<own<instance>, string>
	ftLifecycleProvision = &abi.FuncType{Params: []abi.Type{abi.String, abi.String}, Result: abi.Result(abi.Handle, abi.String)}
	// lifecycle.[method]instance.validate: func(self) -> result<_, string>
	ftLifecycleValidate = &abi.FuncType{Params: []abi.Type{abi.Handle}, Result: resultVoidStrT}
	// lifecycle.[method]instance.cleanup: func(self)
	ftLifecycleCleanup = &abi.FuncType{Params: []abi.Type{abi.Handle}}

	// config.unmarshal-caddyfile: func(module-id: string, tokens: list<token>) -> result<json, string>
	ftConfigUnmarshalCaddyfile = &abi.FuncType{Params: []abi.Type{abi.String, abi.List(tokenT)}, Result: abi.Result(abi.String, abi.String)}

	// http-handler.serve: func(inst, req, resp) -> result<_, plugin-error>
	ftHTTPHandlerServe = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.Handle, abi.Handle}, Result: resultVoidPerrT}

	// http-matcher.matches: func(inst, req) -> result<bool, string>
	ftHTTPMatcherMatches = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.Handle}, Result: abi.Result(abi.Bool, abi.String)}

	// fs.open: func(inst, path: string) -> result<own<file>, string>
	ftFSOpen = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: abi.Result(abi.Handle, abi.String)}
	// fs.stat: func(inst, path: string) -> result<file-info, string>
	ftFSStat = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: resultFileInfoStrT}
	// fs.read-dir: func(inst, path: string) -> result<list<file-info>, string>
	ftFSReadDir = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: abi.Result(abi.List(fileInfoT), abi.String)}
	// fs.[method]file.read: func(self, max: u64) -> result<tuple<list<u8>, bool>, string>
	ftFSFileRead = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.U64}, Result: resultBytesEOFStrT}
	// fs.[method]file.seek: func(self, offset: s64, whence: u8) -> result<u64, string>
	ftFSFileSeek = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.S64, abi.U8}, Result: abi.Result(abi.U64, abi.String)}
	// fs.[method]file.stat: func(self) -> result<file-info, string>
	ftFSFileStat = &abi.FuncType{Params: []abi.Type{abi.Handle}, Result: resultFileInfoStrT}

	// tls-issuer.issuer-key: func(inst) -> string
	ftTLSIssuerKey = &abi.FuncType{Params: []abi.Type{abi.Handle}, Result: abi.String}
	// tls-issuer.issue: func(inst, csr-der: list<u8>) -> result<issued-certificate, string>
	ftTLSIssuerIssue = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.List(abi.U8)}, Result: abi.Result(issuedCertT, abi.String)}

	// tls-cert-loader.load-certificates: func(inst) -> result<list<certificate-key-pair>, string>
	ftTLSCertLoaderLoad = &abi.FuncType{Params: []abi.Type{abi.Handle}, Result: abi.Result(abi.List(certKeyPairT), abi.String)}

	// storage-provider (each takes a borrow<instance> first).
	ftSPStore    = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String, abi.List(abi.U8)}, Result: resultVoidStrT}
	ftSPLoad     = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: resultBytesStrT}
	ftSPDelete   = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: resultVoidStrT}
	ftSPExists   = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: abi.Bool}
	ftSPListKeys = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String, abi.Bool}, Result: resultStringsStrT}
	ftSPStat     = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: resultKeyInfoStrT}
	ftSPLock     = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: resultVoidStrT}
	ftSPUnlock   = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: resultVoidStrT}

	// event-handler.handle: func(inst, evt: event) -> result<_, handler-error>
	ftEventHandlerHandle = &abi.FuncType{Params: []abi.Type{abi.Handle, eventT}, Result: abi.Result(nil, handlerErrorT)}

	// upstream-source.get-upstreams: func(inst, req) -> result<list<upstream>, string>
	ftUpstreamSourceGetUpstreams = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.Handle}, Result: resultUpstreamsStrT}

	// dns-provider (each takes a borrow<instance> first; every function
	// returns result<list<dns-record>, string>).
	resultDNSRecordsStrT = abi.Result(abi.List(dnsRecordT), abi.String)
	// dns-provider.get-records: func(inst, zone: string) -> result<list<dns-record>, string>
	ftDNSGetRecords = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String}, Result: resultDNSRecordsStrT}
	// dns-provider.{append,set,delete}-records: func(inst, zone: string,
	// records: list<dns-record>) -> result<list<dns-record>, string>
	ftDNSMutateRecords = &abi.FuncType{Params: []abi.Type{abi.Handle, abi.String, abi.List(dnsRecordT)}, Result: resultDNSRecordsStrT}
)
