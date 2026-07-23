package abi

import (
	"context"
	"encoding/binary"
	"math"
)

// fakeMemory is a fixed-size in-process implementation of abi.Memory for
// tests, byte-compatible with wazero linear memory semantics.
type fakeMemory struct {
	buf []byte
}

func newFakeMemory(size uint32) *fakeMemory { return &fakeMemory{buf: make([]byte, size)} }

func (m *fakeMemory) in(offset, n uint32) bool {
	return uint64(offset)+uint64(n) <= uint64(len(m.buf))
}

func (m *fakeMemory) ReadUint16Le(offset uint32) (uint16, bool) {
	if !m.in(offset, 2) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(m.buf[offset:]), true
}

func (m *fakeMemory) ReadUint32Le(offset uint32) (uint32, bool) {
	if !m.in(offset, 4) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(m.buf[offset:]), true
}

func (m *fakeMemory) ReadFloat32Le(offset uint32) (float32, bool) {
	v, ok := m.ReadUint32Le(offset)
	return math.Float32frombits(v), ok
}

func (m *fakeMemory) ReadUint64Le(offset uint32) (uint64, bool) {
	if !m.in(offset, 8) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(m.buf[offset:]), true
}

func (m *fakeMemory) ReadFloat64Le(offset uint32) (float64, bool) {
	v, ok := m.ReadUint64Le(offset)
	return math.Float64frombits(v), ok
}

func (m *fakeMemory) Read(offset, byteCount uint32) ([]byte, bool) {
	if !m.in(offset, byteCount) {
		return nil, false
	}
	return m.buf[offset : offset+byteCount : offset+byteCount], true
}

func (m *fakeMemory) WriteUint16Le(offset uint32, v uint16) bool {
	if !m.in(offset, 2) {
		return false
	}
	binary.LittleEndian.PutUint16(m.buf[offset:], v)
	return true
}

func (m *fakeMemory) WriteUint32Le(offset uint32, v uint32) bool {
	if !m.in(offset, 4) {
		return false
	}
	binary.LittleEndian.PutUint32(m.buf[offset:], v)
	return true
}

func (m *fakeMemory) WriteFloat32Le(offset uint32, v float32) bool {
	return m.WriteUint32Le(offset, math.Float32bits(v))
}

func (m *fakeMemory) WriteUint64Le(offset uint32, v uint64) bool {
	if !m.in(offset, 8) {
		return false
	}
	binary.LittleEndian.PutUint64(m.buf[offset:], v)
	return true
}

func (m *fakeMemory) WriteFloat64Le(offset uint32, v float64) bool {
	return m.WriteUint64Le(offset, math.Float64bits(v))
}

func (m *fakeMemory) Write(offset uint32, v []byte) bool {
	if !m.in(offset, uint32(len(v))) {
		return false
	}
	copy(m.buf[offset:], v)
	return true
}

var _ Memory = (*fakeMemory)(nil)

// bumpAlloc is a trivial bump allocator over fakeMemory for tests. It
// allocates starting at base to keep low addresses free for the test's own
// fixed placements.
type bumpAlloc struct {
	next uint32
}

func newBumpAlloc(base uint32) *bumpAlloc { return &bumpAlloc{next: base} }

func (b *bumpAlloc) alloc(_ context.Context, size, align uint32) (uint32, error) {
	p := alignUp(b.next, align)
	b.next = p + size
	return p, nil
}
