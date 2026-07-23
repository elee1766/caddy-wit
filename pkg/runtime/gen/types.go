package gen

// types.go defines the Go-side data types for the caddy:plugin@0.1.0 WIT
// package and the private converters between them and the abi engine's
// untyped value mapping (records as []any in field order, option as
// abi.Opt, result as abi.Res, variant as abi.Var).
//
// Converters are defensive: they type-assert every field and return
// descriptive errors instead of panicking, because the values originate in
// guest-controlled linear memory.

import (
	"fmt"

	"github.com/elee1766/caddy-wit/pkg/abi"
)

// Level mirrors caddy:plugin/log.level.
type Level uint8

const (
	LevelDebug Level = 0
	LevelInfo  Level = 1
	LevelWarn  Level = 2
	LevelError Level = 3
)

// DirectivePosition mirrors caddy:plugin/manifest.directive-position.
type DirectivePosition uint8

const (
	DirectiveBefore DirectivePosition = 0
	DirectiveAfter  DirectivePosition = 1
)

// CaddyfileOrder mirrors caddy:plugin/manifest.caddyfile-order.
type CaddyfileOrder struct {
	Position   DirectivePosition
	RelativeTo string
}

// ModuleDecl mirrors caddy:plugin/manifest.module-decl.
type ModuleDecl struct {
	ID             string
	Docs           *string
	CaddyfileOrder *CaddyfileOrder
}

// PluginInfo mirrors caddy:plugin/manifest.plugin-info.
type PluginInfo struct {
	Name    string
	Version *string
	Modules []ModuleDecl
}

// Token mirrors caddy:plugin/config.token.
type Token struct {
	File   string
	Line   uint32
	Text   string
	Quoted bool
}

// PluginError mirrors caddy:plugin/types.plugin-error.
type PluginError struct {
	Message string
	Status  *uint16
}

// KeyInfo mirrors caddy:plugin/types.key-info. Modified is epoch-ms.
type KeyInfo struct {
	Key      string
	Modified int64
	Size     int64
	Terminal bool
}

// Event mirrors caddy:plugin/types.event. Timestamp is epoch-ms; Data is a
// JSON document.
type Event struct {
	ID        string
	Name      string
	Timestamp int64
	Origin    string
	Data      string
}

// FileInfo mirrors caddy:plugin/fs.file-info. ModTime is epoch-ms.
type FileInfo struct {
	Name    string
	Size    uint64
	Mode    uint32
	ModTime int64
	Dir     bool
}

// IssuedCertificate mirrors caddy:plugin/tls-issuer.issued-certificate.
type IssuedCertificate struct {
	CertificatePEM []byte
	Metadata       *string
}

// CertificateKeyPair mirrors caddy:plugin/tls-cert-loader.certificate-key-pair.
type CertificateKeyPair struct {
	CertificatePEM []byte
	KeyPEM         []byte
	Tags           []string
}

// DNSRecord mirrors caddy:plugin/dns-provider.dns-record (libdns
// semantics: names relative to the zone).
type DNSRecord struct {
	RRType     string
	Name       string
	Value      string
	TTLSeconds uint32
	Priority   *uint16
}

// Upstream mirrors caddy:plugin/upstream-source.upstream.
type Upstream struct {
	Dial        string
	MaxRequests uint32
}

// HTTPRequestOptions mirrors caddy:plugin/host-http.request-options.
type HTTPRequestOptions struct {
	TimeoutMS        *uint32
	MaxResponseBytes *uint64
	FollowRedirects  *bool
}

// HTTPResponse mirrors caddy:plugin/host-http.response.
type HTTPResponse struct {
	Status  uint16
	Headers []abi.Pair[string, string]
	Body    []byte
}

// HandlerErrorTag discriminates caddy:plugin/event-handler.handler-error.
type HandlerErrorTag uint8

const (
	HandlerErrorAborted HandlerErrorTag = 0
	HandlerErrorMessage HandlerErrorTag = 1
)

// HandlerError mirrors caddy:plugin/event-handler.handler-error. Message is
// only meaningful when Tag == HandlerErrorMessage.
type HandlerError struct {
	Tag     HandlerErrorTag
	Message string
}

// --- low-level assertion helpers ---

func asString(v any, what string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("gen: %s: expected string, got %T", what, v)
	}
	return s, nil
}

func asBool(v any, what string) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("gen: %s: expected bool, got %T", what, v)
	}
	return b, nil
}

func asU32(v any, what string) (uint32, error) {
	n, ok := v.(uint32)
	if !ok {
		return 0, fmt.Errorf("gen: %s: expected uint32, got %T", what, v)
	}
	return n, nil
}

func asU64(v any, what string) (uint64, error) {
	n, ok := v.(uint64)
	if !ok {
		return 0, fmt.Errorf("gen: %s: expected uint64, got %T", what, v)
	}
	return n, nil
}

func asS64(v any, what string) (int64, error) {
	n, ok := v.(int64)
	if !ok {
		return 0, fmt.Errorf("gen: %s: expected int64, got %T", what, v)
	}
	return n, nil
}

func asBytes(v any, what string) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("gen: %s: expected []byte, got %T", what, v)
	}
	return b, nil
}

// recordFields asserts v is a []any with exactly n fields.
func recordFields(v any, n int, what string) ([]any, error) {
	fields, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("gen: %s: expected []any record, got %T", what, v)
	}
	if len(fields) != n {
		return nil, fmt.Errorf("gen: %s: expected %d fields, got %d", what, n, len(fields))
	}
	return fields, nil
}

func listElems(v any, what string) ([]any, error) {
	elems, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("gen: %s: expected []any list, got %T", what, v)
	}
	return elems, nil
}

func optStringFromAny(v any, what string) (*string, error) {
	o, ok := v.(abi.Opt)
	if !ok {
		return nil, fmt.Errorf("gen: %s: expected abi.Opt, got %T", what, v)
	}
	if !o.Some {
		return nil, nil
	}
	s, err := asString(o.Val, what)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func optStringToAny(p *string) abi.Opt {
	if p == nil {
		return abi.None
	}
	return abi.SomeVal(*p)
}

// optFromAny lifts an option<T> wire value for scalar payload types.
func optFromAny[T any](v any, what string) (*T, error) {
	o, ok := v.(abi.Opt)
	if !ok {
		return nil, fmt.Errorf("gen: %s: expected abi.Opt, got %T", what, v)
	}
	if !o.Some {
		return nil, nil
	}
	p, ok := o.Val.(T)
	if !ok {
		return nil, fmt.Errorf("gen: %s: expected %T payload, got %T", what, p, o.Val)
	}
	return &p, nil
}

// optToAny lowers *T into an option<T> wire value.
func optToAny[T any](p *T) abi.Opt {
	if p == nil {
		return abi.None
	}
	return abi.SomeVal(*p)
}

func stringsFromAny(v any, what string) ([]string, error) {
	elems, err := listElems(v, what)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(elems))
	for i, e := range elems {
		s, serr := asString(e, fmt.Sprintf("%s[%d]", what, i))
		if serr != nil {
			return nil, serr
		}
		out = append(out, s)
	}
	return out, nil
}

func stringsToAny(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

// pairsToAny lowers []abi.Pair[string,string] to a list<tuple<string,string>>
// wire value.
func pairsToAny(pairs []abi.Pair[string, string]) []any {
	out := make([]any, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, []any{p.V0, p.V1})
	}
	return out
}

// pairsFromAny lifts a list<tuple<string,string>> wire value.
func pairsFromAny(v any, what string) ([]abi.Pair[string, string], error) {
	elems, err := listElems(v, what)
	if err != nil {
		return nil, err
	}
	out := make([]abi.Pair[string, string], 0, len(elems))
	for i, e := range elems {
		f, ferr := recordFields(e, 2, fmt.Sprintf("%s[%d]", what, i))
		if ferr != nil {
			return nil, ferr
		}
		k, kerr := asString(f[0], fmt.Sprintf("%s[%d].0", what, i))
		if kerr != nil {
			return nil, kerr
		}
		val, verr := asString(f[1], fmt.Sprintf("%s[%d].1", what, i))
		if verr != nil {
			return nil, verr
		}
		out = append(out, abi.Pair[string, string]{V0: k, V1: val})
	}
	return out, nil
}

// --- module-decl / plugin-info ---

// caddyfileOrderFromAny lifts an option<caddyfile-order> wire value. A none
// option yields nil. The enum discriminant crosses the wire as uint32.
func caddyfileOrderFromAny(v any, what string) (*CaddyfileOrder, error) {
	o, ok := v.(abi.Opt)
	if !ok {
		return nil, fmt.Errorf("gen: %s: expected abi.Opt, got %T", what, v)
	}
	if !o.Some {
		return nil, nil
	}
	f, err := recordFields(o.Val, 2, what)
	if err != nil {
		return nil, err
	}
	pos, err := asU32(f[0], what+".position")
	if err != nil {
		return nil, err
	}
	if pos > uint32(DirectiveAfter) {
		return nil, fmt.Errorf("gen: %s.position: enum case %d out of range", what, pos)
	}
	rel, err := asString(f[1], what+".relative-to")
	if err != nil {
		return nil, err
	}
	return &CaddyfileOrder{Position: DirectivePosition(pos), RelativeTo: rel}, nil
}

// caddyfileOrderToAny lowers *CaddyfileOrder into an option<caddyfile-order>
// wire value. A nil pointer yields none.
func caddyfileOrderToAny(co *CaddyfileOrder) abi.Opt {
	if co == nil {
		return abi.None
	}
	return abi.SomeVal([]any{uint32(co.Position), co.RelativeTo})
}

func moduleDeclFromAny(v any) (ModuleDecl, error) {
	f, err := recordFields(v, 3, "module-decl")
	if err != nil {
		return ModuleDecl{}, err
	}
	id, err := asString(f[0], "module-decl.id")
	if err != nil {
		return ModuleDecl{}, err
	}
	docs, err := optStringFromAny(f[1], "module-decl.docs")
	if err != nil {
		return ModuleDecl{}, err
	}
	order, err := caddyfileOrderFromAny(f[2], "module-decl.caddyfile-order")
	if err != nil {
		return ModuleDecl{}, err
	}
	return ModuleDecl{ID: id, Docs: docs, CaddyfileOrder: order}, nil
}

func moduleDeclToAny(md ModuleDecl) []any {
	return []any{md.ID, optStringToAny(md.Docs), caddyfileOrderToAny(md.CaddyfileOrder)}
}

func pluginInfoFromAny(v any) (PluginInfo, error) {
	f, err := recordFields(v, 3, "plugin-info")
	if err != nil {
		return PluginInfo{}, err
	}
	name, err := asString(f[0], "plugin-info.name")
	if err != nil {
		return PluginInfo{}, err
	}
	version, err := optStringFromAny(f[1], "plugin-info.version")
	if err != nil {
		return PluginInfo{}, err
	}
	elems, err := listElems(f[2], "plugin-info.modules")
	if err != nil {
		return PluginInfo{}, err
	}
	mods := make([]ModuleDecl, 0, len(elems))
	for i, e := range elems {
		md, merr := moduleDeclFromAny(e)
		if merr != nil {
			return PluginInfo{}, fmt.Errorf("gen: plugin-info.modules[%d]: %w", i, merr)
		}
		mods = append(mods, md)
	}
	return PluginInfo{Name: name, Version: version, Modules: mods}, nil
}

func pluginInfoToAny(pi PluginInfo) []any {
	mods := make([]any, 0, len(pi.Modules))
	for _, md := range pi.Modules {
		mods = append(mods, moduleDeclToAny(md))
	}
	return []any{pi.Name, optStringToAny(pi.Version), mods}
}

// --- token ---

func tokenFromAny(v any) (Token, error) {
	f, err := recordFields(v, 4, "token")
	if err != nil {
		return Token{}, err
	}
	file, err := asString(f[0], "token.file")
	if err != nil {
		return Token{}, err
	}
	line, err := asU32(f[1], "token.line")
	if err != nil {
		return Token{}, err
	}
	text, err := asString(f[2], "token.text")
	if err != nil {
		return Token{}, err
	}
	quoted, err := asBool(f[3], "token.quoted")
	if err != nil {
		return Token{}, err
	}
	return Token{File: file, Line: line, Text: text, Quoted: quoted}, nil
}

func tokenToAny(t Token) []any {
	return []any{t.File, t.Line, t.Text, t.Quoted}
}

func tokensToAny(tokens []Token) []any {
	out := make([]any, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, tokenToAny(t))
	}
	return out
}

// --- plugin-error ---

func pluginErrorFromAny(v any) (PluginError, error) {
	f, err := recordFields(v, 2, "plugin-error")
	if err != nil {
		return PluginError{}, err
	}
	msg, err := asString(f[0], "plugin-error.message")
	if err != nil {
		return PluginError{}, err
	}
	o, ok := f[1].(abi.Opt)
	if !ok {
		return PluginError{}, fmt.Errorf("gen: plugin-error.status: expected abi.Opt, got %T", f[1])
	}
	pe := PluginError{Message: msg}
	if o.Some {
		s, sok := o.Val.(uint16)
		if !sok {
			return PluginError{}, fmt.Errorf("gen: plugin-error.status: expected uint16, got %T", o.Val)
		}
		pe.Status = &s
	}
	return pe, nil
}

func pluginErrorToAny(pe PluginError) []any {
	status := abi.None
	if pe.Status != nil {
		status = abi.SomeVal(*pe.Status)
	}
	return []any{pe.Message, status}
}

// --- key-info ---

func keyInfoFromAny(v any) (KeyInfo, error) {
	f, err := recordFields(v, 4, "key-info")
	if err != nil {
		return KeyInfo{}, err
	}
	key, err := asString(f[0], "key-info.key")
	if err != nil {
		return KeyInfo{}, err
	}
	modified, err := asS64(f[1], "key-info.modified")
	if err != nil {
		return KeyInfo{}, err
	}
	size, err := asS64(f[2], "key-info.size")
	if err != nil {
		return KeyInfo{}, err
	}
	terminal, err := asBool(f[3], "key-info.terminal")
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{Key: key, Modified: modified, Size: size, Terminal: terminal}, nil
}

func keyInfoToAny(ki KeyInfo) []any {
	return []any{ki.Key, ki.Modified, ki.Size, ki.Terminal}
}

// --- event ---

func eventFromAny(v any) (Event, error) {
	f, err := recordFields(v, 5, "event")
	if err != nil {
		return Event{}, err
	}
	id, err := asString(f[0], "event.id")
	if err != nil {
		return Event{}, err
	}
	name, err := asString(f[1], "event.name")
	if err != nil {
		return Event{}, err
	}
	ts, err := asS64(f[2], "event.timestamp")
	if err != nil {
		return Event{}, err
	}
	origin, err := asString(f[3], "event.origin")
	if err != nil {
		return Event{}, err
	}
	data, err := asString(f[4], "event.data")
	if err != nil {
		return Event{}, err
	}
	return Event{ID: id, Name: name, Timestamp: ts, Origin: origin, Data: data}, nil
}

func eventToAny(ev Event) []any {
	return []any{ev.ID, ev.Name, ev.Timestamp, ev.Origin, ev.Data}
}

// --- file-info ---

func fileInfoFromAny(v any) (FileInfo, error) {
	f, err := recordFields(v, 5, "file-info")
	if err != nil {
		return FileInfo{}, err
	}
	name, err := asString(f[0], "file-info.name")
	if err != nil {
		return FileInfo{}, err
	}
	size, err := asU64(f[1], "file-info.size")
	if err != nil {
		return FileInfo{}, err
	}
	mode, err := asU32(f[2], "file-info.mode")
	if err != nil {
		return FileInfo{}, err
	}
	modTime, err := asS64(f[3], "file-info.mod-time")
	if err != nil {
		return FileInfo{}, err
	}
	dir, err := asBool(f[4], "file-info.dir")
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{Name: name, Size: size, Mode: mode, ModTime: modTime, Dir: dir}, nil
}

func fileInfoToAny(fi FileInfo) []any {
	return []any{fi.Name, fi.Size, fi.Mode, fi.ModTime, fi.Dir}
}

func fileInfosFromAny(v any) ([]FileInfo, error) {
	elems, err := listElems(v, "list<file-info>")
	if err != nil {
		return nil, err
	}
	out := make([]FileInfo, 0, len(elems))
	for i, e := range elems {
		fi, ferr := fileInfoFromAny(e)
		if ferr != nil {
			return nil, fmt.Errorf("gen: list<file-info>[%d]: %w", i, ferr)
		}
		out = append(out, fi)
	}
	return out, nil
}

// --- issued-certificate ---

func issuedCertificateFromAny(v any) (IssuedCertificate, error) {
	f, err := recordFields(v, 2, "issued-certificate")
	if err != nil {
		return IssuedCertificate{}, err
	}
	pem, err := asBytes(f[0], "issued-certificate.certificate-pem")
	if err != nil {
		return IssuedCertificate{}, err
	}
	meta, err := optStringFromAny(f[1], "issued-certificate.metadata")
	if err != nil {
		return IssuedCertificate{}, err
	}
	return IssuedCertificate{CertificatePEM: pem, Metadata: meta}, nil
}

func issuedCertificateToAny(ic IssuedCertificate) []any {
	pem := ic.CertificatePEM
	if pem == nil {
		pem = []byte{}
	}
	return []any{pem, optStringToAny(ic.Metadata)}
}

// --- certificate-key-pair ---

func certificateKeyPairFromAny(v any) (CertificateKeyPair, error) {
	f, err := recordFields(v, 3, "certificate-key-pair")
	if err != nil {
		return CertificateKeyPair{}, err
	}
	cert, err := asBytes(f[0], "certificate-key-pair.certificate-pem")
	if err != nil {
		return CertificateKeyPair{}, err
	}
	key, err := asBytes(f[1], "certificate-key-pair.key-pem")
	if err != nil {
		return CertificateKeyPair{}, err
	}
	tags, err := stringsFromAny(f[2], "certificate-key-pair.tags")
	if err != nil {
		return CertificateKeyPair{}, err
	}
	return CertificateKeyPair{CertificatePEM: cert, KeyPEM: key, Tags: tags}, nil
}

func certificateKeyPairToAny(p CertificateKeyPair) []any {
	cert := p.CertificatePEM
	if cert == nil {
		cert = []byte{}
	}
	key := p.KeyPEM
	if key == nil {
		key = []byte{}
	}
	return []any{cert, key, stringsToAny(p.Tags)}
}

func certificateKeyPairsFromAny(v any) ([]CertificateKeyPair, error) {
	elems, err := listElems(v, "list<certificate-key-pair>")
	if err != nil {
		return nil, err
	}
	out := make([]CertificateKeyPair, 0, len(elems))
	for i, e := range elems {
		p, perr := certificateKeyPairFromAny(e)
		if perr != nil {
			return nil, fmt.Errorf("gen: list<certificate-key-pair>[%d]: %w", i, perr)
		}
		out = append(out, p)
	}
	return out, nil
}

// --- handler-error ---

func handlerErrorFromAny(v any) (HandlerError, error) {
	vv, ok := v.(abi.Var)
	if !ok {
		return HandlerError{}, fmt.Errorf("gen: handler-error: expected abi.Var, got %T", v)
	}
	switch vv.Case {
	case uint32(HandlerErrorAborted):
		return HandlerError{Tag: HandlerErrorAborted}, nil
	case uint32(HandlerErrorMessage):
		msg, err := asString(vv.Val, "handler-error.message")
		if err != nil {
			return HandlerError{}, err
		}
		return HandlerError{Tag: HandlerErrorMessage, Message: msg}, nil
	default:
		return HandlerError{}, fmt.Errorf("gen: handler-error: case %d out of range", vv.Case)
	}
}

func handlerErrorToAny(he HandlerError) abi.Var {
	if he.Tag == HandlerErrorMessage {
		return abi.Var{Case: uint32(HandlerErrorMessage), Val: he.Message}
	}
	return abi.Var{Case: uint32(HandlerErrorAborted)}
}

// --- dns-record ---

func dnsRecordFromAny(v any) (DNSRecord, error) {
	f, err := recordFields(v, 5, "dns-record")
	if err != nil {
		return DNSRecord{}, err
	}
	rrType, err := asString(f[0], "dns-record.rr-type")
	if err != nil {
		return DNSRecord{}, err
	}
	name, err := asString(f[1], "dns-record.name")
	if err != nil {
		return DNSRecord{}, err
	}
	value, err := asString(f[2], "dns-record.value")
	if err != nil {
		return DNSRecord{}, err
	}
	ttl, err := asU32(f[3], "dns-record.ttl-seconds")
	if err != nil {
		return DNSRecord{}, err
	}
	priority, err := optFromAny[uint16](f[4], "dns-record.priority")
	if err != nil {
		return DNSRecord{}, err
	}
	return DNSRecord{RRType: rrType, Name: name, Value: value, TTLSeconds: ttl, Priority: priority}, nil
}

func dnsRecordToAny(r DNSRecord) []any {
	return []any{r.RRType, r.Name, r.Value, r.TTLSeconds, optToAny(r.Priority)}
}

func dnsRecordsFromAny(v any) ([]DNSRecord, error) {
	elems, err := listElems(v, "list<dns-record>")
	if err != nil {
		return nil, err
	}
	out := make([]DNSRecord, 0, len(elems))
	for i, e := range elems {
		r, rerr := dnsRecordFromAny(e)
		if rerr != nil {
			return nil, fmt.Errorf("gen: list<dns-record>[%d]: %w", i, rerr)
		}
		out = append(out, r)
	}
	return out, nil
}

func dnsRecordsToAny(recs []DNSRecord) []any {
	out := make([]any, 0, len(recs))
	for _, r := range recs {
		out = append(out, dnsRecordToAny(r))
	}
	return out
}

// --- host-http request-options / response ---

// httpRequestOptionsFromAny lifts an option<request-options> wire value.
// A none option yields nil.
func httpRequestOptionsFromAny(v any, what string) (*HTTPRequestOptions, error) {
	o, ok := v.(abi.Opt)
	if !ok {
		return nil, fmt.Errorf("gen: %s: expected abi.Opt, got %T", what, v)
	}
	if !o.Some {
		return nil, nil
	}
	f, err := recordFields(o.Val, 3, what)
	if err != nil {
		return nil, err
	}
	timeoutMS, err := optFromAny[uint32](f[0], what+".timeout-ms")
	if err != nil {
		return nil, err
	}
	maxBytes, err := optFromAny[uint64](f[1], what+".max-response-bytes")
	if err != nil {
		return nil, err
	}
	follow, err := optFromAny[bool](f[2], what+".follow-redirects")
	if err != nil {
		return nil, err
	}
	return &HTTPRequestOptions{TimeoutMS: timeoutMS, MaxResponseBytes: maxBytes, FollowRedirects: follow}, nil
}

// httpRequestOptionsToAny lowers *HTTPRequestOptions into an
// option<request-options> wire value. A nil pointer yields none.
func httpRequestOptionsToAny(o *HTTPRequestOptions) abi.Opt {
	if o == nil {
		return abi.None
	}
	return abi.SomeVal([]any{optToAny(o.TimeoutMS), optToAny(o.MaxResponseBytes), optToAny(o.FollowRedirects)})
}

func httpResponseFromAny(v any) (HTTPResponse, error) {
	f, err := recordFields(v, 3, "response")
	if err != nil {
		return HTTPResponse{}, err
	}
	status, ok := f[0].(uint16)
	if !ok {
		return HTTPResponse{}, fmt.Errorf("gen: response.status: expected uint16, got %T", f[0])
	}
	headers, err := pairsFromAny(f[1], "response.headers")
	if err != nil {
		return HTTPResponse{}, err
	}
	body, err := asBytes(f[2], "response.body")
	if err != nil {
		return HTTPResponse{}, err
	}
	return HTTPResponse{Status: status, Headers: headers, Body: body}, nil
}

func httpResponseToAny(r HTTPResponse) []any {
	body := r.Body
	if body == nil {
		body = []byte{}
	}
	return []any{r.Status, pairsToAny(r.Headers), body}
}

// --- upstream ---

func upstreamFromAny(v any) (Upstream, error) {
	f, err := recordFields(v, 2, "upstream")
	if err != nil {
		return Upstream{}, err
	}
	dial, err := asString(f[0], "upstream.dial")
	if err != nil {
		return Upstream{}, err
	}
	maxReq, err := asU32(f[1], "upstream.max-requests")
	if err != nil {
		return Upstream{}, err
	}
	return Upstream{Dial: dial, MaxRequests: maxReq}, nil
}

func upstreamsFromAny(v any) ([]Upstream, error) {
	elems, err := listElems(v, "list<upstream>")
	if err != nil {
		return nil, err
	}
	out := make([]Upstream, 0, len(elems))
	for i, e := range elems {
		u, uerr := upstreamFromAny(e)
		if uerr != nil {
			return nil, fmt.Errorf("gen: list<upstream>[%d]: %w", i, uerr)
		}
		out = append(out, u)
	}
	return out, nil
}
