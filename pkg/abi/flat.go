package abi

import (
	"context"
	"fmt"
	"math"

	"github.com/tetratelabs/wazero/api"
)

// flatReader consumes core values from a stack slice.
type flatReader struct {
	stack []uint64
	pos   int
}

func (r *flatReader) next() (uint64, error) {
	if r.pos >= len(r.stack) {
		return 0, fmt.Errorf("abi: flat value underflow at index %d", r.pos)
	}
	v := r.stack[r.pos]
	r.pos++
	return v, nil
}

// LiftFlat decodes a sequence of values of the given types from flattened
// core values, dereferencing strings/lists from memory. It is used to read
// guest arguments inside host functions.
func LiftFlat(mem Memory, ts []Type, stack []uint64) ([]any, error) {
	r := &flatReader{stack: stack}
	out := make([]any, len(ts))
	for i, t := range ts {
		v, err := liftFlatOne(mem, t, r)
		if err != nil {
			return nil, fmt.Errorf("abi: lifting flat value %d: %w", i, err)
		}
		out[i] = v
	}
	return out, nil
}

func liftFlatOne(mem Memory, t Type, r *flatReader) (any, error) {
	switch tt := t.(type) {
	case *primitive:
		raw, err := r.next()
		if err != nil {
			return nil, err
		}
		return liftFlatPrimitive(tt, raw)
	case *stringType:
		p, err := r.next()
		if err != nil {
			return nil, err
		}
		l, err := r.next()
		if err != nil {
			return nil, err
		}
		return ReadString(mem, uint32(p), uint32(l))
	case *enumType:
		raw, err := r.next()
		if err != nil {
			return nil, err
		}
		d := uint32(raw)
		if d >= tt.numCases {
			return nil, fmt.Errorf("abi: enum discriminant %d out of range (%d cases)", d, tt.numCases)
		}
		return d, nil
	case *listType:
		p, err := r.next()
		if err != nil {
			return nil, err
		}
		l, err := r.next()
		if err != nil {
			return nil, err
		}
		return loadListElems(mem, tt.elem, uint32(p), uint32(l))
	case *recordType:
		fields := make([]any, len(tt.fields))
		for i, f := range tt.fields {
			v, err := liftFlatOne(mem, f, r)
			if err != nil {
				return nil, fmt.Errorf("record field %d: %w", i, err)
			}
			fields[i] = v
		}
		return fields, nil
	case *variantType:
		raw, err := r.next()
		if err != nil {
			return nil, err
		}
		d := uint32(raw)
		if d >= uint32(len(tt.cases)) {
			return nil, fmt.Errorf("variant discriminant %d out of range (%d cases)", d, len(tt.cases))
		}
		// All cases share the joined flat slots; every case must consume
		// exactly the joined width, so we read the full window and re-read
		// the case's own flats from it.
		joined := len(tt.flat) - 1
		window := make([]uint64, joined)
		for i := range window {
			window[i], err = r.next()
			if err != nil {
				return nil, err
			}
		}
		var payload any
		if c := tt.cases[d]; c != nil {
			sub := &flatReader{stack: window}
			payload, err = liftFlatOne(mem, c, sub)
			if err != nil {
				return nil, fmt.Errorf("variant case %d payload: %w", d, err)
			}
		}
		return wrapVariant(tt, d, payload), nil
	default:
		return nil, fmt.Errorf("abi: LiftFlat: unsupported type %T", t)
	}
}

func liftFlatPrimitive(t *primitive, raw uint64) (any, error) {
	switch t.kind {
	case KindBool:
		return uint32(raw) != 0, nil
	case KindU8:
		return uint8(raw), nil
	case KindS8:
		return int8(uint8(raw)), nil
	case KindU16:
		return uint16(raw), nil
	case KindS16:
		return int16(uint16(raw)), nil
	case KindU32:
		return uint32(raw), nil
	case KindS32:
		return int32(uint32(raw)), nil
	case KindU64:
		return raw, nil
	case KindS64:
		return int64(raw), nil
	case KindF32:
		return api.DecodeF32(raw), nil
	case KindF64:
		return api.DecodeF64(raw), nil
	case KindChar:
		v := uint32(raw)
		if v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF) {
			return nil, fmt.Errorf("abi: invalid char scalar value %#x", v)
		}
		return rune(v), nil
	case KindHandle:
		return uint32(raw), nil
	default:
		return nil, fmt.Errorf("abi: liftFlatPrimitive: unsupported kind %v", t.kind)
	}
}

// LowerFlat encodes values of the given types into flattened core values,
// copying strings/lists into guest memory via alloc. It is used to build
// guest call arguments.
func LowerFlat(ctx context.Context, mem Memory, alloc Alloc, ts []Type, vals []any) ([]uint64, error) {
	if len(ts) != len(vals) {
		return nil, fmt.Errorf("abi: LowerFlat: %d types but %d values", len(ts), len(vals))
	}
	var out []uint64
	for i, t := range ts {
		flat, err := lowerFlatOne(ctx, mem, alloc, t, vals[i])
		if err != nil {
			return nil, fmt.Errorf("abi: lowering flat value %d: %w", i, err)
		}
		out = append(out, flat...)
	}
	return out, nil
}

func lowerFlatOne(ctx context.Context, mem Memory, alloc Alloc, t Type, v any) ([]uint64, error) {
	switch tt := t.(type) {
	case *primitive:
		raw, err := lowerFlatPrimitive(tt, v)
		if err != nil {
			return nil, err
		}
		return []uint64{raw}, nil
	case *stringType:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("abi: expected string, got %T", v)
		}
		p, l, err := lowerString(ctx, mem, alloc, s)
		if err != nil {
			return nil, err
		}
		return []uint64{uint64(p), uint64(l)}, nil
	case *enumType:
		d, ok := v.(uint32)
		if !ok {
			return nil, fmt.Errorf("abi: expected uint32 enum case, got %T", v)
		}
		if d >= tt.numCases {
			return nil, fmt.Errorf("abi: enum case %d out of range (%d cases)", d, tt.numCases)
		}
		return []uint64{uint64(d)}, nil
	case *listType:
		p, l, err := lowerList(ctx, mem, alloc, tt.elem, v)
		if err != nil {
			return nil, err
		}
		return []uint64{uint64(p), uint64(l)}, nil
	case *recordType:
		fields, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("abi: expected []any record fields, got %T", v)
		}
		if len(fields) != len(tt.fields) {
			return nil, fmt.Errorf("abi: record has %d fields, got %d values", len(tt.fields), len(fields))
		}
		var out []uint64
		for i, f := range tt.fields {
			flat, err := lowerFlatOne(ctx, mem, alloc, f, fields[i])
			if err != nil {
				return nil, fmt.Errorf("record field %d: %w", i, err)
			}
			out = append(out, flat...)
		}
		return out, nil
	case *variantType:
		d, payload, err := unwrapVariant(tt, v)
		if err != nil {
			return nil, err
		}
		out := make([]uint64, len(tt.flat))
		out[0] = uint64(d)
		if c := tt.cases[d]; c != nil {
			flat, err := lowerFlatOne(ctx, mem, alloc, c, payload)
			if err != nil {
				return nil, fmt.Errorf("variant case %d payload: %w", d, err)
			}
			copy(out[1:], flat)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("abi: LowerFlat: unsupported type %T", t)
	}
}

func lowerFlatPrimitive(t *primitive, v any) (uint64, error) {
	badType := func() (uint64, error) {
		return 0, fmt.Errorf("abi: bad value %T for %v", v, t.kind)
	}
	switch t.kind {
	case KindBool:
		b, ok := v.(bool)
		if !ok {
			return badType()
		}
		if b {
			return 1, nil
		}
		return 0, nil
	case KindU8:
		x, ok := v.(uint8)
		if !ok {
			return badType()
		}
		return uint64(x), nil
	case KindS8:
		x, ok := v.(int8)
		if !ok {
			return badType()
		}
		return uint64(uint8(x)), nil
	case KindU16:
		x, ok := v.(uint16)
		if !ok {
			return badType()
		}
		return uint64(x), nil
	case KindS16:
		x, ok := v.(int16)
		if !ok {
			return badType()
		}
		return uint64(uint16(x)), nil
	case KindU32:
		x, ok := v.(uint32)
		if !ok {
			return badType()
		}
		return uint64(x), nil
	case KindS32:
		x, ok := v.(int32)
		if !ok {
			return badType()
		}
		return uint64(uint32(x)), nil
	case KindU64:
		x, ok := v.(uint64)
		if !ok {
			return badType()
		}
		return x, nil
	case KindS64:
		x, ok := v.(int64)
		if !ok {
			return badType()
		}
		return uint64(x), nil
	case KindF32:
		x, ok := v.(float32)
		if !ok {
			return badType()
		}
		return api.EncodeF32(x), nil
	case KindF64:
		x, ok := v.(float64)
		if !ok {
			return badType()
		}
		return api.EncodeF64(x), nil
	case KindChar:
		x, ok := v.(rune)
		if !ok {
			return badType()
		}
		if x < 0 || x > 0x10FFFF || (x >= 0xD800 && x <= 0xDFFF) {
			return 0, fmt.Errorf("abi: invalid rune %#x", x)
		}
		return uint64(uint32(x)), nil
	case KindHandle:
		x, ok := v.(uint32)
		if !ok {
			return badType()
		}
		return uint64(x), nil
	default:
		return badType()
	}
}

// sanity guard: list lengths and string lengths fit u32 on this platform.
var _ = math.MaxUint32
