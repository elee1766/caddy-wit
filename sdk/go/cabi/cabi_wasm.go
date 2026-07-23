//go:build wasm

package cabi

import "unsafe"

// pinned keeps canonical-ABI allocations reachable so TinyGo's GC never
// frees memory the host still references.
//
// Trade-off: allocations are pinned for the module's lifetime, leaking a
// few bytes per host->guest call that carries strings/lists. That is fine
// for DNS providers (a handful of calls per ACME challenge); a future
// version could use an arena reset between calls once the host guarantees
// it no longer reads previous buffers.
var pinned [][]byte

// cabiRealloc implements the Canonical ABI allocator. The host calls it to
// place strings/lists into guest linear memory before invoking exports.
//
//go:wasmexport cabi_realloc
func cabiRealloc(ptr, oldSize, align, newSize uint32) uint32 {
	if align == 0 {
		align = 1
	}
	if newSize == 0 {
		return align // any non-zero aligned pointer is acceptable
	}
	buf := make([]byte, newSize+align)
	pinned = append(pinned, buf)
	addr := uint32(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	aligned := (addr + align - 1) &^ (align - 1)
	if ptr != 0 && oldSize > 0 {
		old := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), oldSize)
		copy(unsafe.Slice((*byte)(unsafe.Pointer(uintptr(aligned))), newSize), old)
	}
	return aligned
}
