package abi

import (
	"context"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/tetratelabs/wazero/api"
)

// Memory is the subset of wazero's api.Memory used by this package.
// api.Memory satisfies it structurally (api.Memory itself is sealed and
// cannot be implemented by fakes, which is why this narrower interface
// exists): pass mod.Memory() wherever a Memory is needed.
type Memory interface {
	ReadUint16Le(offset uint32) (uint16, bool)
	ReadUint32Le(offset uint32) (uint32, bool)
	ReadUint64Le(offset uint32) (uint64, bool)
	ReadFloat32Le(offset uint32) (float32, bool)
	ReadFloat64Le(offset uint32) (float64, bool)
	Read(offset, byteCount uint32) ([]byte, bool)
	WriteUint16Le(offset uint32, v uint16) bool
	WriteUint32Le(offset uint32, v uint32) bool
	WriteUint64Le(offset uint32, v uint64) bool
	WriteFloat32Le(offset uint32, v float32) bool
	WriteFloat64Le(offset uint32, v float64) bool
	Write(offset uint32, v []byte) bool
}

// readByte reads one byte via Read (the interface deliberately omits
// ReadByte/WriteByte to avoid io.ByteReader signature collisions in vet).
func readByte(mem Memory, offset uint32) (byte, bool) {
	b, ok := mem.Read(offset, 1)
	if !ok {
		return 0, false
	}
	return b[0], true
}

func writeByte(mem Memory, offset uint32, v byte) bool {
	return mem.Write(offset, []byte{v})
}

// Alloc allocates size bytes with the given alignment inside guest linear
// memory and returns the pointer. Production code uses GuestAlloc; tests use
// a bump allocator over fake memory.
type Alloc func(ctx context.Context, size, align uint32) (uint32, error)

// GuestAlloc returns an Alloc backed by the guest's exported cabi_realloc.
func GuestAlloc(mod api.Module) Alloc {
	return func(ctx context.Context, size, align uint32) (uint32, error) {
		fn := mod.ExportedFunction("cabi_realloc")
		if fn == nil {
			return 0, fmt.Errorf("abi: guest does not export cabi_realloc")
		}
		// cabi_realloc(original_ptr, original_size, alignment, new_size)
		res, err := fn.Call(ctx, 0, 0, uint64(align), uint64(size))
		if err != nil {
			return 0, fmt.Errorf("abi: cabi_realloc failed: %w", err)
		}
		if len(res) != 1 {
			return 0, fmt.Errorf("abi: cabi_realloc returned %d results, want 1", len(res))
		}
		return uint32(res[0]), nil
	}
}

// ReadString reads a UTF-8 string of the given byte length from memory.
func ReadString(mem Memory, ptr, length uint32) (string, error) {
	if length == 0 {
		return "", nil
	}
	b, ok := mem.Read(ptr, length)
	if !ok {
		return "", fmt.Errorf("abi: string read out of range: ptr=%d len=%d", ptr, length)
	}
	return string(b), nil
}

// ReadBytes reads a byte slice (copy) from memory.
func ReadBytes(mem Memory, ptr, length uint32) ([]byte, error) {
	if length == 0 {
		return []byte{}, nil
	}
	b, ok := mem.Read(ptr, length)
	if !ok {
		return nil, fmt.Errorf("abi: bytes read out of range: ptr=%d len=%d", ptr, length)
	}
	out := make([]byte, length)
	copy(out, b)
	return out, nil
}

// Load reads a value of type t at ptr from linear memory, returning its Go
// representation (see values.go for the mapping).
func Load(mem Memory, t Type, ptr uint32) (any, error) {
	switch tt := t.(type) {
	case *primitive:
		return loadPrimitive(mem, tt, ptr)
	case *stringType:
		p, ok1 := mem.ReadUint32Le(ptr)
		l, ok2 := mem.ReadUint32Le(ptr + 4)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("abi: string header read out of range at %d", ptr)
		}
		return ReadString(mem, p, l)
	case *enumType:
		d, err := loadDisc(mem, ptr, discSize(tt.numCases))
		if err != nil {
			return nil, err
		}
		if d >= tt.numCases {
			return nil, fmt.Errorf("abi: enum discriminant %d out of range (%d cases)", d, tt.numCases)
		}
		return d, nil
	case *listType:
		p, ok1 := mem.ReadUint32Le(ptr)
		l, ok2 := mem.ReadUint32Le(ptr + 4)
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("abi: list header read out of range at %d", ptr)
		}
		return loadListElems(mem, tt.elem, p, l)
	case *recordType:
		fields := make([]any, len(tt.fields))
		for i, f := range tt.fields {
			v, err := Load(mem, f, ptr+tt.offsets[i])
			if err != nil {
				return nil, fmt.Errorf("abi: record field %d: %w", i, err)
			}
			fields[i] = v
		}
		return fields, nil
	case *variantType:
		d, err := loadDisc(mem, ptr, discSize(uint32(len(tt.cases))))
		if err != nil {
			return nil, err
		}
		if d >= uint32(len(tt.cases)) {
			return nil, fmt.Errorf("abi: variant discriminant %d out of range (%d cases)", d, len(tt.cases))
		}
		var payload any
		if c := tt.cases[d]; c != nil {
			payload, err = Load(mem, c, ptr+tt.payload)
			if err != nil {
				return nil, fmt.Errorf("abi: variant case %d payload: %w", d, err)
			}
		}
		return wrapVariant(tt, d, payload), nil
	default:
		return nil, fmt.Errorf("abi: Load: unsupported type %T", t)
	}
}

func wrapVariant(t *variantType, disc uint32, payload any) any {
	switch t.kind {
	case KindOption:
		if disc == 0 {
			return None
		}
		return SomeVal(payload)
	case KindResult:
		return Res{IsErr: disc == 1, Val: payload}
	default:
		return Var{Case: disc, Val: payload}
	}
}

// unwrapVariant validates v against t and returns (disc, payload).
func unwrapVariant(t *variantType, v any) (uint32, any, error) {
	switch t.kind {
	case KindOption:
		o, ok := v.(Opt)
		if !ok {
			return 0, nil, fmt.Errorf("abi: expected abi.Opt, got %T", v)
		}
		if !o.Some {
			return 0, nil, nil
		}
		return 1, o.Val, nil
	case KindResult:
		r, ok := v.(Res)
		if !ok {
			return 0, nil, fmt.Errorf("abi: expected abi.Res, got %T", v)
		}
		if r.IsErr {
			return 1, r.Val, nil
		}
		return 0, r.Val, nil
	default:
		vv, ok := v.(Var)
		if !ok {
			return 0, nil, fmt.Errorf("abi: expected abi.Var, got %T", v)
		}
		if vv.Case >= uint32(len(t.cases)) {
			return 0, nil, fmt.Errorf("abi: variant case %d out of range (%d cases)", vv.Case, len(t.cases))
		}
		return vv.Case, vv.Val, nil
	}
}

func loadPrimitive(mem Memory, t *primitive, ptr uint32) (any, error) {
	fail := func() (any, error) {
		return nil, fmt.Errorf("abi: %v read out of range at %d", t.kind, ptr)
	}
	switch t.kind {
	case KindBool:
		b, ok := readByte(mem, ptr)
		if !ok {
			return fail()
		}
		return b != 0, nil
	case KindU8:
		b, ok := readByte(mem, ptr)
		if !ok {
			return fail()
		}
		return b, nil
	case KindS8:
		b, ok := readByte(mem, ptr)
		if !ok {
			return fail()
		}
		return int8(b), nil
	case KindU16:
		v, ok := mem.ReadUint16Le(ptr)
		if !ok {
			return fail()
		}
		return v, nil
	case KindS16:
		v, ok := mem.ReadUint16Le(ptr)
		if !ok {
			return fail()
		}
		return int16(v), nil
	case KindU32:
		v, ok := mem.ReadUint32Le(ptr)
		if !ok {
			return fail()
		}
		return v, nil
	case KindS32:
		v, ok := mem.ReadUint32Le(ptr)
		if !ok {
			return fail()
		}
		return int32(v), nil
	case KindU64:
		v, ok := mem.ReadUint64Le(ptr)
		if !ok {
			return fail()
		}
		return v, nil
	case KindS64:
		v, ok := mem.ReadUint64Le(ptr)
		if !ok {
			return fail()
		}
		return int64(v), nil
	case KindF32:
		v, ok := mem.ReadFloat32Le(ptr)
		if !ok {
			return fail()
		}
		return v, nil
	case KindF64:
		v, ok := mem.ReadFloat64Le(ptr)
		if !ok {
			return fail()
		}
		return v, nil
	case KindChar:
		v, ok := mem.ReadUint32Le(ptr)
		if !ok {
			return fail()
		}
		if v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF) {
			return nil, fmt.Errorf("abi: invalid char scalar value %#x", v)
		}
		return rune(v), nil
	case KindHandle:
		v, ok := mem.ReadUint32Le(ptr)
		if !ok {
			return fail()
		}
		return v, nil
	default:
		return nil, fmt.Errorf("abi: loadPrimitive: unsupported kind %v", t.kind)
	}
}

func loadDisc(mem Memory, ptr, size uint32) (uint32, error) {
	switch size {
	case 1:
		b, ok := readByte(mem, ptr)
		if !ok {
			return 0, fmt.Errorf("abi: discriminant read out of range at %d", ptr)
		}
		return uint32(b), nil
	case 2:
		v, ok := mem.ReadUint16Le(ptr)
		if !ok {
			return 0, fmt.Errorf("abi: discriminant read out of range at %d", ptr)
		}
		return uint32(v), nil
	default:
		v, ok := mem.ReadUint32Le(ptr)
		if !ok {
			return 0, fmt.Errorf("abi: discriminant read out of range at %d", ptr)
		}
		return v, nil
	}
}

func loadListElems(mem Memory, elem Type, ptr, length uint32) (any, error) {
	if kindOf(elem) == KindU8 {
		return ReadBytes(mem, ptr, length)
	}
	stride := alignUp(elem.Size(), elem.Align())
	out := make([]any, length)
	for i := uint32(0); i < length; i++ {
		v, err := Load(mem, elem, ptr+i*stride)
		if err != nil {
			return nil, fmt.Errorf("abi: list element %d: %w", i, err)
		}
		out[i] = v
	}
	return out, nil
}

// Store writes a value of type t at ptr. Nested strings and lists are
// allocated in guest memory via alloc.
func Store(ctx context.Context, mem Memory, alloc Alloc, t Type, ptr uint32, v any) error {
	switch tt := t.(type) {
	case *primitive:
		return storePrimitive(mem, tt, ptr, v)
	case *stringType:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("abi: expected string, got %T", v)
		}
		p, l, err := lowerString(ctx, mem, alloc, s)
		if err != nil {
			return err
		}
		if !mem.WriteUint32Le(ptr, p) || !mem.WriteUint32Le(ptr+4, l) {
			return fmt.Errorf("abi: string header write out of range at %d", ptr)
		}
		return nil
	case *enumType:
		d, ok := v.(uint32)
		if !ok {
			return fmt.Errorf("abi: expected uint32 enum case, got %T", v)
		}
		if d >= tt.numCases {
			return fmt.Errorf("abi: enum case %d out of range (%d cases)", d, tt.numCases)
		}
		return storeDisc(mem, ptr, discSize(tt.numCases), d)
	case *listType:
		p, l, err := lowerList(ctx, mem, alloc, tt.elem, v)
		if err != nil {
			return err
		}
		if !mem.WriteUint32Le(ptr, p) || !mem.WriteUint32Le(ptr+4, l) {
			return fmt.Errorf("abi: list header write out of range at %d", ptr)
		}
		return nil
	case *recordType:
		fields, ok := v.([]any)
		if !ok {
			return fmt.Errorf("abi: expected []any record fields, got %T", v)
		}
		if len(fields) != len(tt.fields) {
			return fmt.Errorf("abi: record has %d fields, got %d values", len(tt.fields), len(fields))
		}
		for i, f := range tt.fields {
			if err := Store(ctx, mem, alloc, f, ptr+tt.offsets[i], fields[i]); err != nil {
				return fmt.Errorf("abi: record field %d: %w", i, err)
			}
		}
		return nil
	case *variantType:
		d, payload, err := unwrapVariant(tt, v)
		if err != nil {
			return err
		}
		if err := storeDisc(mem, ptr, discSize(uint32(len(tt.cases))), d); err != nil {
			return err
		}
		if c := tt.cases[d]; c != nil {
			if err := Store(ctx, mem, alloc, c, ptr+tt.payload, payload); err != nil {
				return fmt.Errorf("abi: variant case %d payload: %w", d, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("abi: Store: unsupported type %T", t)
	}
}

func storePrimitive(mem Memory, t *primitive, ptr uint32, v any) error {
	outOfRange := func() error {
		return fmt.Errorf("abi: %v write out of range at %d", t.kind, ptr)
	}
	badType := func() error {
		return fmt.Errorf("abi: bad value %T for %v", v, t.kind)
	}
	switch t.kind {
	case KindBool:
		b, ok := v.(bool)
		if !ok {
			return badType()
		}
		var byteVal byte
		if b {
			byteVal = 1
		}
		if !writeByte(mem, ptr, byteVal) {
			return outOfRange()
		}
		return nil
	case KindU8:
		x, ok := v.(uint8)
		if !ok {
			return badType()
		}
		if !writeByte(mem, ptr, x) {
			return outOfRange()
		}
		return nil
	case KindS8:
		x, ok := v.(int8)
		if !ok {
			return badType()
		}
		if !writeByte(mem, ptr, byte(x)) {
			return outOfRange()
		}
		return nil
	case KindU16:
		x, ok := v.(uint16)
		if !ok {
			return badType()
		}
		if !mem.WriteUint16Le(ptr, x) {
			return outOfRange()
		}
		return nil
	case KindS16:
		x, ok := v.(int16)
		if !ok {
			return badType()
		}
		if !mem.WriteUint16Le(ptr, uint16(x)) {
			return outOfRange()
		}
		return nil
	case KindU32:
		x, ok := v.(uint32)
		if !ok {
			return badType()
		}
		if !mem.WriteUint32Le(ptr, x) {
			return outOfRange()
		}
		return nil
	case KindS32:
		x, ok := v.(int32)
		if !ok {
			return badType()
		}
		if !mem.WriteUint32Le(ptr, uint32(x)) {
			return outOfRange()
		}
		return nil
	case KindU64:
		x, ok := v.(uint64)
		if !ok {
			return badType()
		}
		if !mem.WriteUint64Le(ptr, x) {
			return outOfRange()
		}
		return nil
	case KindS64:
		x, ok := v.(int64)
		if !ok {
			return badType()
		}
		if !mem.WriteUint64Le(ptr, uint64(x)) {
			return outOfRange()
		}
		return nil
	case KindF32:
		x, ok := v.(float32)
		if !ok {
			return badType()
		}
		if !mem.WriteFloat32Le(ptr, x) {
			return outOfRange()
		}
		return nil
	case KindF64:
		x, ok := v.(float64)
		if !ok {
			return badType()
		}
		if !mem.WriteFloat64Le(ptr, x) {
			return outOfRange()
		}
		return nil
	case KindChar:
		x, ok := v.(rune)
		if !ok {
			return badType()
		}
		if !utf8.ValidRune(x) {
			return fmt.Errorf("abi: invalid rune %#x", x)
		}
		if !mem.WriteUint32Le(ptr, uint32(x)) {
			return outOfRange()
		}
		return nil
	case KindHandle:
		x, ok := v.(uint32)
		if !ok {
			return badType()
		}
		if !mem.WriteUint32Le(ptr, x) {
			return outOfRange()
		}
		return nil
	default:
		return fmt.Errorf("abi: storePrimitive: unsupported kind %v", t.kind)
	}
}

func storeDisc(mem Memory, ptr, size, d uint32) error {
	var ok bool
	switch size {
	case 1:
		ok = writeByte(mem, ptr, byte(d))
	case 2:
		ok = mem.WriteUint16Le(ptr, uint16(d))
	default:
		ok = mem.WriteUint32Le(ptr, d)
	}
	if !ok {
		return fmt.Errorf("abi: discriminant write out of range at %d", ptr)
	}
	return nil
}

// lowerString copies s into guest memory, returning (ptr, len).
func lowerString(ctx context.Context, mem Memory, alloc Alloc, s string) (uint32, uint32, error) {
	if len(s) > math.MaxUint32 {
		return 0, 0, fmt.Errorf("abi: string too long: %d bytes", len(s))
	}
	if len(s) == 0 {
		// A zero-length string does not require an allocation; the
		// canonical ABI permits any aligned pointer. Use 0.
		return 0, 0, nil
	}
	ptr, err := alloc(ctx, uint32(len(s)), 1)
	if err != nil {
		return 0, 0, err
	}
	if !mem.Write(ptr, []byte(s)) {
		return 0, 0, fmt.Errorf("abi: string body write out of range at %d", ptr)
	}
	return ptr, uint32(len(s)), nil
}

// lowerList copies a list value into guest memory, returning (ptr, len).
func lowerList(ctx context.Context, mem Memory, alloc Alloc, elem Type, v any) (uint32, uint32, error) {
	if kindOf(elem) == KindU8 {
		b, ok := v.([]byte)
		if !ok {
			return 0, 0, fmt.Errorf("abi: expected []byte for list<u8>, got %T", v)
		}
		if len(b) == 0 {
			return 0, 0, nil
		}
		ptr, err := alloc(ctx, uint32(len(b)), 1)
		if err != nil {
			return 0, 0, err
		}
		if !mem.Write(ptr, b) {
			return 0, 0, fmt.Errorf("abi: list<u8> body write out of range at %d", ptr)
		}
		return ptr, uint32(len(b)), nil
	}
	elems, ok := v.([]any)
	if !ok {
		return 0, 0, fmt.Errorf("abi: expected []any for list, got %T", v)
	}
	if len(elems) == 0 {
		return 0, 0, nil
	}
	stride := alignUp(elem.Size(), elem.Align())
	ptr, err := alloc(ctx, stride*uint32(len(elems)), elem.Align())
	if err != nil {
		return 0, 0, err
	}
	for i, e := range elems {
		if err := Store(ctx, mem, alloc, elem, ptr+uint32(i)*stride, e); err != nil {
			return 0, 0, fmt.Errorf("abi: list element %d: %w", i, err)
		}
	}
	return ptr, uint32(len(elems)), nil
}
