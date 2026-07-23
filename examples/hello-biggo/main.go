// Experiment: a caddy-wit guest compiled with NATIVE Go (gc toolchain,
// GOOS=wasip1 GOARCH=wasm, -buildmode=c-shared) — no TinyGo.
//
// This exists to prove that big Go's go:wasmexport/go:wasmimport rules are
// sufficient for the component-model canonical ABI when all boundary
// signatures use only scalars and unsafe.Pointer, i.e. that native-Go
// support is purely a binding-generation problem (wit-bindgen-go emits
// typed pointers, which big Go rejects), not a Go runtime/compiler gap.
//
// It hand-writes the canonical ABI for a useful subset of the caddy:plugin
// world: manifest.describe, the lifecycle resource, and http-handler.serve.
//
// Build:
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
package main

import (
	"encoding/binary"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Canonical ABI plumbing (what a big-Go wit-bindgen mode would generate).
// ---------------------------------------------------------------------------

// pinned keeps host-visible allocations alive; Go's wasm GC is non-moving,
// so pinned buffers have stable addresses.
var pinned [][]byte

func alloc(size, align uint32) uint32 {
	if size == 0 {
		size = 1
	}
	buf := make([]byte, size+align)
	pinned = append(pinned, buf)
	addr := uint32(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	return (addr + align - 1) &^ (align - 1)
}

//go:wasmexport cabi_realloc
func cabiRealloc(ptr, oldSize, align, newSize uint32) uint32 {
	if align == 0 {
		align = 1
	}
	if newSize == 0 {
		return align
	}
	p := alloc(newSize, align)
	if ptr != 0 && oldSize > 0 {
		copy(mem(p, newSize), mem(ptr, oldSize))
	}
	return p
}

// mem gives a byte view of linear memory at ptr.
func mem(ptr, size uint32) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), size)
}

func putU32(ptr, v uint32)     { binary.LittleEndian.PutUint32(mem(ptr, 4), v) }
func getU32(ptr uint32) uint32 { return binary.LittleEndian.Uint32(mem(ptr, 4)) }

// lowerString copies s into pinned linear memory, returning (ptr, len).
func lowerString(s string) (uint32, uint32) {
	if len(s) == 0 {
		return 0, 0
	}
	p := alloc(uint32(len(s)), 1)
	copy(mem(p, uint32(len(s))), s)
	return p, uint32(len(s))
}

func liftString(ptr, length uint32) string {
	if length == 0 {
		return ""
	}
	return string(mem(ptr, length))
}

// ---------------------------------------------------------------------------
// Host imports (log). Signature uses only scalars: allowed by big Go.
// ---------------------------------------------------------------------------

//go:wasmimport caddy:plugin/log@0.1.0 log
func hostLog(level uint32, msgPtr, msgLen, fieldsPtr, fieldsLen uint32)

func logInfo(msg string) {
	p, l := lowerString(msg)
	hostLog(1 /* info */, p, l, 0, 0)
}

// ---------------------------------------------------------------------------
// Guest-exported resource builtins for lifecycle.instance.
// ---------------------------------------------------------------------------

//go:wasmimport [export]caddy:plugin/lifecycle@0.1.0 [resource-new]instance
func instanceResourceNew(rep uint32) uint32

// ---------------------------------------------------------------------------
// manifest.describe: func() -> plugin-info
// plugin-info layout: name(ptr,len) version(disc,pad,ptr,len) modules(ptr,len)
// module-decl layout (36 bytes): id ptr@0 len@4; docs disc@8, str ptr@12
// len@16; caddyfile-order disc@20, payload@24: position u8@24 (enum
// directive-position: 0=before, 1=after), relative-to ptr@28 len@32.
// ---------------------------------------------------------------------------

//go:wasmexport caddy:plugin/manifest@0.1.0#describe
func describe() uint32 {
	// one module-decl
	md := alloc(36, 4)
	idP, idL := lowerString("http.handlers.wit_hello_biggo")
	putU32(md+0, idP)
	putU32(md+4, idL)
	docsP, docsL := lowerString("native-Go (gc) canonical ABI experiment")
	mem(md+8, 1)[0] = 1 // docs: some
	putU32(md+12, docsP)
	putU32(md+16, docsL)
	mem(md+20, 1)[0] = 1 // caddyfile-order: some
	mem(md+24, 1)[0] = 0 // position: before
	relP, relL := lowerString("respond")
	putU32(md+28, relP)
	putU32(md+32, relL)

	// plugin-info (28 bytes)
	pi := alloc(28, 4)
	nameP, nameL := lowerString("hello-biggo")
	putU32(pi+0, nameP)
	putU32(pi+4, nameL)
	verP, verL := lowerString("0.1.0")
	mem(pi+8, 1)[0] = 1 // version: some
	putU32(pi+12, verP)
	putU32(pi+16, verL)
	putU32(pi+20, md) // modules ptr
	putU32(pi+24, 1)  // modules len
	return pi
}

// ---------------------------------------------------------------------------
// lifecycle.instance
// ---------------------------------------------------------------------------

var (
	instances        = map[uint32]string{} // rep -> message
	nextRep   uint32 = 1
)

// provision: static func(module-id: string, config: json)
//
//	-> result<own<instance>, string>
//
// Core shape: (i32 x4) -> i32 ptr to result{disc u8; pad; handle u32 | string}
//
//go:wasmexport caddy:plugin/lifecycle@0.1.0#[static]instance.provision
func provision(idPtr, idLen, cfgPtr, cfgLen uint32) uint32 {
	out := alloc(12, 4)
	id := liftString(idPtr, idLen)
	if id != "http.handlers.wit_hello_biggo" {
		p, l := lowerString("unknown module id: " + id)
		mem(out, 1)[0] = 1 // err
		putU32(out+4, p)
		putU32(out+8, l)
		return out
	}
	// Cheap "config parsing": the config is {"message":"..."} or empty.
	msg := "hello from native go"
	cfg := liftString(cfgPtr, cfgLen)
	if i := indexOf(cfg, `"message":"`); i >= 0 {
		rest := cfg[i+len(`"message":"`):]
		if j := indexOf(rest, `"`); j >= 0 && rest[:j] != "" {
			msg = rest[:j]
		}
	}
	rep := nextRep
	nextRep++
	instances[rep] = msg
	logInfo("wit_hello_biggo provisioned")
	handle := instanceResourceNew(rep)
	mem(out, 1)[0] = 0 // ok
	putU32(out+4, handle)
	return out
}

//go:wasmexport caddy:plugin/lifecycle@0.1.0#[method]instance.validate
func validate(rep uint32) uint32 {
	out := alloc(12, 4)
	if instances[rep] == "" {
		p, l := lowerString("message must not be empty")
		mem(out, 1)[0] = 1
		putU32(out+4, p)
		putU32(out+8, l)
		return out
	}
	mem(out, 1)[0] = 0
	return out
}

//go:wasmexport caddy:plugin/lifecycle@0.1.0#[method]instance.cleanup
func cleanup(rep uint32) {}

//go:wasmexport caddy:plugin/lifecycle@0.1.0#[dtor]instance
func instanceDtor(rep uint32) { delete(instances, rep) }

// ---------------------------------------------------------------------------
// http-handler.serve: func(inst, req, resp) -> result<_, plugin-error>
// plugin-error layout (12 bytes): message(ptr,len) status(disc,pad? -> at 8:
// disc u8, u16 at 10)... result<_, plugin-error>: disc u8 @0, payload @4:
// message ptr@4 len@8, status disc@12 val@14, size 16.
// ---------------------------------------------------------------------------

//go:wasmimport caddy:plugin/http-types@0.1.0 [method]request.path
func requestPath(self uint32, retPtr uint32)

//go:wasmimport caddy:plugin/http-types@0.1.0 [method]response-writer.set-header
func responseSetHeader(self, namePtr, nameLen, valPtr, valLen uint32)

//go:wasmimport caddy:plugin/http-types@0.1.0 [method]response-writer.write-status
func responseWriteStatus(self, status uint32)

//go:wasmimport caddy:plugin/http-types@0.1.0 [method]response-writer.write
func responseWrite(self, dataPtr, dataLen, retPtr uint32)

//go:wasmimport caddy:plugin/http-types@0.1.0 next
func hostNext(req, resp, retPtr uint32)

//go:wasmexport caddy:plugin/http-handler@0.1.0#serve
func serve(inst, req, resp uint32) uint32 {
	out := alloc(16, 4)
	msg := instances[inst]

	hp, hl := lowerString("X-Wit-Hello-BigGo")
	vp, vl := lowerString("1")
	responseSetHeader(resp, hp, hl, vp, vl)

	// request.path() -> string via retptr
	pathRet := alloc(8, 4)
	requestPath(req, pathRet)
	path := liftString(getU32(pathRet), getU32(pathRet+4))

	if path == "/hello" {
		responseWriteStatus(resp, 200)
		bp, bl := lowerString(msg)
		wRet := alloc(16, 8) // result<u64, string>
		responseWrite(resp, bp, bl, wRet)
		mem(out, 1)[0] = 0 // ok (ignore write result details)
		return out
	}

	// next(req, resp) -> result<_, plugin-error>; forward its result.
	hostNext(req, resp, out)
	return out
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// main is required; with -buildmode=c-shared the runtime initializes via
// _initialize and exported functions can be called afterwards.
func main() {}
