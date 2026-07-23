// Package abi implements the host side of the WebAssembly Component Model
// Canonical ABI for core-wasm guests produced by wit-bindgen, running on
// wazero.
//
// Rather than generating static lift/lower code per interface, this package
// is a small interpreter driven by type descriptors: higher layers (see
// runtime/gen) describe each function's signature with Type values and the
// engine performs memory layout, flattening, guest allocation, and calling
// convention details at call time.
//
// All layout rules follow the Canonical ABI specification:
// https://github.com/WebAssembly/component-model/blob/main/design/mvp/CanonicalABI.md
package abi

import (
	"github.com/tetratelabs/wazero/api"
)

// Type describes a component-model value type and its Canonical ABI
// properties. Implementations are immutable and safe for concurrent use.
type Type interface {
	// Size is the byte size of the type in linear memory ("element size").
	Size() uint32
	// Align is the alignment of the type in linear memory.
	Align() uint32
	// Flat is the flattened core-wasm representation of the type.
	Flat() []api.ValueType
}

// Kind discriminates the concrete descriptor behind a Type.
type Kind uint8

const (
	KindBool Kind = iota
	KindU8
	KindU16
	KindU32
	KindU64
	KindS8
	KindS16
	KindS32
	KindS64
	KindF32
	KindF64
	KindChar
	KindString
	KindHandle // own<T> or borrow<T>: an i32 handle
	KindEnum
	KindList
	KindRecord // also tuples
	KindVariant
	KindOption // variant<none, some(T)> with specialized Go mapping
	KindResult // variant<ok(T), err(E)> with specialized Go mapping
)

// primitive is a scalar type descriptor.
type primitive struct {
	kind  Kind
	size  uint32
	align uint32
	flat  api.ValueType
}

func (p *primitive) Size() uint32          { return p.size }
func (p *primitive) Align() uint32         { return p.align }
func (p *primitive) Flat() []api.ValueType { return []api.ValueType{p.flat} }

// kindOf returns the Kind of any Type produced by this package.
func kindOf(t Type) Kind {
	switch tt := t.(type) {
	case *primitive:
		return tt.kind
	case *stringType:
		return KindString
	case *enumType:
		return KindEnum
	case *listType:
		return KindList
	case *recordType:
		return KindRecord
	case *variantType:
		return tt.kind
	default:
		panic("abi: unknown Type implementation")
	}
}

// Scalar type singletons.
//
// Canonical ABI element sizes and alignments ("alignment" and "element size"
// sections of CanonicalABI.md): bool/u8/s8 = 1 byte; u16/s16 = 2; u32/s32,
// f32, char = 4; u64/s64, f64 = 8. All 32-bit-or-narrower integers (and
// bool, char, enum discriminants, resource handles) flatten to core i32.
var (
	Bool   Type = &primitive{KindBool, 1, 1, api.ValueTypeI32}
	U8     Type = &primitive{KindU8, 1, 1, api.ValueTypeI32}
	U16    Type = &primitive{KindU16, 2, 2, api.ValueTypeI32}
	U32    Type = &primitive{KindU32, 4, 4, api.ValueTypeI32}
	U64    Type = &primitive{KindU64, 8, 8, api.ValueTypeI64}
	S8     Type = &primitive{KindS8, 1, 1, api.ValueTypeI32}
	S16    Type = &primitive{KindS16, 2, 2, api.ValueTypeI32}
	S32    Type = &primitive{KindS32, 4, 4, api.ValueTypeI32}
	S64    Type = &primitive{KindS64, 8, 8, api.ValueTypeI64}
	F32    Type = &primitive{KindF32, 4, 4, api.ValueTypeF32}
	F64    Type = &primitive{KindF64, 8, 8, api.ValueTypeF64}
	Char   Type = &primitive{KindChar, 4, 4, api.ValueTypeI32}
	Handle Type = &primitive{KindHandle, 4, 4, api.ValueTypeI32}
)

// stringType implements the string descriptor: (ptr: u32, len: u32).
type stringType struct{}

func (*stringType) Size() uint32          { return 8 }
func (*stringType) Align() uint32         { return 4 }
func (*stringType) Flat() []api.ValueType { return []api.ValueType{api.ValueTypeI32, api.ValueTypeI32} }

// String is the UTF-8 string type descriptor.
var String Type = &stringType{}

// enumType is an enum with a case count. It is represented in memory as its
// discriminant only and flattens to i32.
type enumType struct {
	numCases uint32
}

func (e *enumType) Size() uint32          { return discSize(e.numCases) }
func (e *enumType) Align() uint32         { return discSize(e.numCases) }
func (e *enumType) Flat() []api.ValueType { return []api.ValueType{api.ValueTypeI32} }

// Enum returns an enum descriptor with the given number of cases.
func Enum(numCases uint32) Type {
	if numCases == 0 {
		panic("abi: enum must have at least one case")
	}
	return &enumType{numCases: numCases}
}

// discSize returns the discriminant byte size for a case count, per the
// Canonical ABI "discriminant type" rule.
func discSize(numCases uint32) uint32 {
	switch {
	case numCases <= 1<<8:
		return 1
	case numCases <= 1<<16:
		return 2
	default:
		return 4
	}
}

// listType is list<Elem>: (ptr: u32, len: u32) with elements stored
// contiguously at stride alignUp(elem.Size(), elem.Align()).
type listType struct {
	elem Type
}

func (l *listType) Size() uint32          { return 8 }
func (l *listType) Align() uint32         { return 4 }
func (l *listType) Flat() []api.ValueType { return []api.ValueType{api.ValueTypeI32, api.ValueTypeI32} }

// List returns a list descriptor with the given element type.
func List(elem Type) Type { return &listType{elem: elem} }

// recordType is a record (or tuple): fields laid out in order at aligned
// offsets; size rounded up to the record alignment.
type recordType struct {
	fields  []Type
	offsets []uint32
	size    uint32
	align   uint32
	flat    []api.ValueType
}

// Record returns a record/tuple descriptor with positional fields.
func Record(fields ...Type) Type {
	r := &recordType{fields: fields, align: 1}
	var off uint32
	for _, f := range fields {
		if a := f.Align(); a > r.align {
			r.align = a
		}
		off = alignUp(off, f.Align())
		r.offsets = append(r.offsets, off)
		off += f.Size()
		r.flat = append(r.flat, f.Flat()...)
	}
	r.size = alignUp(off, r.align)
	return r
}

func (r *recordType) Size() uint32          { return r.size }
func (r *recordType) Align() uint32         { return r.align }
func (r *recordType) Flat() []api.ValueType { return r.flat }

// variantType covers variants and the specialized option/result forms.
// A nil case type means the case carries no payload.
type variantType struct {
	kind    Kind // KindVariant, KindOption, or KindResult
	cases   []Type
	size    uint32
	align   uint32
	payload uint32 // payload offset
	flat    []api.ValueType
}

func newVariant(kind Kind, cases []Type) *variantType {
	v := &variantType{kind: kind, cases: cases}
	ds := discSize(uint32(len(cases)))
	v.align = ds
	var maxPayloadAlign, maxPayloadEnd uint32 = 1, 0
	for _, c := range cases {
		if c == nil {
			continue
		}
		if a := c.Align(); a > maxPayloadAlign {
			maxPayloadAlign = a
		}
	}
	if maxPayloadAlign > v.align {
		v.align = maxPayloadAlign
	}
	v.payload = alignUp(ds, maxPayloadAlign)
	for _, c := range cases {
		if c == nil {
			continue
		}
		if end := v.payload + c.Size(); end > maxPayloadEnd {
			maxPayloadEnd = end
		}
	}
	if maxPayloadEnd < v.payload {
		maxPayloadEnd = v.payload
	}
	v.size = alignUp(maxPayloadEnd, v.align)

	// Flattening: i32 discriminant followed by the joined case flats
	// (CanonicalABI.md "flat_variant"): flats of equal type stay, an i32/f32
	// mix becomes i32, and anything involving a 64-bit type becomes i64.
	var joined []api.ValueType
	for _, c := range cases {
		if c == nil {
			continue
		}
		for i, ft := range c.Flat() {
			if i < len(joined) {
				joined[i] = join(joined[i], ft)
			} else {
				joined = append(joined, ft)
			}
		}
	}
	v.flat = append([]api.ValueType{api.ValueTypeI32}, joined...)
	return v
}

func (v *variantType) Size() uint32          { return v.size }
func (v *variantType) Align() uint32         { return v.align }
func (v *variantType) Flat() []api.ValueType { return v.flat }

// Variant returns a general variant descriptor. A nil case has no payload.
func Variant(cases ...Type) Type {
	if len(cases) == 0 {
		panic("abi: variant must have at least one case")
	}
	return newVariant(KindVariant, cases)
}

// Option returns option<t>, mapped to the Go Opt value.
func Option(t Type) Type {
	if t == nil {
		panic("abi: option payload must be non-nil")
	}
	return newVariant(KindOption, []Type{nil, t})
}

// Result returns result<ok, err>, mapped to the Go Res value. Either side
// may be nil for "no payload".
func Result(ok, err Type) Type {
	return newVariant(KindResult, []Type{ok, err})
}

// join merges two flat core types per the Canonical ABI join() rule.
func join(a, b api.ValueType) api.ValueType {
	if a == b {
		return a
	}
	if (a == api.ValueTypeI32 && b == api.ValueTypeF32) || (a == api.ValueTypeF32 && b == api.ValueTypeI32) {
		return api.ValueTypeI32
	}
	return api.ValueTypeI64
}

func alignUp(n, align uint32) uint32 {
	if align == 0 {
		return n
	}
	return (n + align - 1) &^ (align - 1)
}
