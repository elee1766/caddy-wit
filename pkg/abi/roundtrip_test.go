package abi

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// battery is a set of (type, value) pairs covering every kind, reused by
// the memory and flat round-trip tests.
var battery = []struct {
	name string
	t    Type
	v    any
}{
	{"bool-true", Bool, true},
	{"bool-false", Bool, false},
	{"u8", U8, uint8(0xAB)},
	{"s8-neg", S8, int8(-5)},
	{"u16", U16, uint16(0xBEEF)},
	{"s16-neg", S16, int16(-12345)},
	{"u32", U32, uint32(0xDEADBEEF)},
	{"s32-neg", S32, int32(-123456789)},
	{"u64", U64, uint64(0xDEADBEEFCAFEBABE)},
	{"s64-neg", S64, int64(-1234567890123)},
	{"f32", F32, float32(3.25)},
	{"f64", F64, float64(-2.5e300)},
	{"char", Char, 'é'},
	{"char-emoji", Char, '🎉'},
	{"handle", Handle, uint32(7)},
	{"enum", Enum(4), uint32(3)},
	{"string-empty", String, ""},
	{"string-ascii", String, "hello caddy"},
	{"string-unicode", String, "héllo wörld 你好 🎉"},
	{"bytes-empty", List(U8), []byte{}},
	{"bytes", List(U8), []byte{1, 2, 3, 254, 255}},
	{"list-strings", List(String), []any{"a", "", "c"}},
	{"list-empty", List(String), []any{}},
	{"list-of-records", List(Record(String, U32)), []any{
		[]any{"x", uint32(1)},
		[]any{"y", uint32(2)},
	}},
	{"record-empty", Record(), []any{}},
	{"record-plugin-error", Record(String, Option(U16)), []any{"boom", SomeVal(uint16(502))}},
	{"record-key-info", Record(String, S64, S64, Bool), []any{"k", int64(123), int64(-9), true}},
	{"record-event", Record(String, String, S64, String, String),
		[]any{"id-1", "tls", int64(1720500000000), "http.handlers.x", `{"a":1}`}},
	{"option-none", Option(String), None},
	{"option-some", Option(String), SomeVal("val")},
	{"option-nested", Option(Option(U16)), SomeVal(SomeVal(uint16(9)))},
	{"result-ok-empty", Result(nil, String), OkVal(nil)},
	{"result-err-string", Result(nil, String), ErrVal("it broke")},
	{"result-ok-u64", Result(U64, String), OkVal(uint64(42))},
	{"result-err-record", Result(U32, Record(String, Option(U16))),
		ErrVal([]any{"denied", SomeVal(uint16(403))})},
	{"variant-nopayload", Variant(nil, String), Var{Case: 0}},
	{"variant-payload", Variant(nil, String), Var{Case: 1, Val: "msg"}},
	{"deep-nesting", List(Record(String, List(Record(U32, String)))), []any{
		[]any{"outer", []any{
			[]any{uint32(1), "inner-1"},
			[]any{uint32(2), "inner-2"},
		}},
	}},
}

func TestStoreLoadRoundTrip(t *testing.T) {
	for _, tc := range battery {
		t.Run(tc.name, func(t *testing.T) {
			mem := newFakeMemory(1 << 20)
			ba := newBumpAlloc(4096)
			ptr := uint32(64)
			if err := Store(context.Background(), mem, ba.alloc, tc.t, ptr, tc.v); err != nil {
				t.Fatalf("Store: %v", err)
			}
			got, err := Load(mem, tc.t, ptr)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !reflect.DeepEqual(got, tc.v) {
				t.Errorf("round trip mismatch:\n got %#v\nwant %#v", got, tc.v)
			}
		})
	}
}

func TestFlatRoundTrip(t *testing.T) {
	for _, tc := range battery {
		t.Run(tc.name, func(t *testing.T) {
			mem := newFakeMemory(1 << 20)
			ba := newBumpAlloc(4096)
			flat, err := LowerFlat(context.Background(), mem, ba.alloc, []Type{tc.t}, []any{tc.v})
			if err != nil {
				t.Fatalf("LowerFlat: %v", err)
			}
			if want := len(tc.t.Flat()); len(flat) != want {
				t.Fatalf("LowerFlat produced %d core values, want %d", len(flat), want)
			}
			got, err := LiftFlat(mem, []Type{tc.t}, flat)
			if err != nil {
				t.Fatalf("LiftFlat: %v", err)
			}
			if !reflect.DeepEqual(got[0], tc.v) {
				t.Errorf("flat round trip mismatch:\n got %#v\nwant %#v", got[0], tc.v)
			}
		})
	}
}

func TestMultiParamFlatRoundTrip(t *testing.T) {
	mem := newFakeMemory(1 << 20)
	ba := newBumpAlloc(4096)
	ts := []Type{String, U32, List(U8), Option(String), Handle}
	vals := []any{"module-id", uint32(9), []byte{1, 2}, SomeVal("cfg"), uint32(3)}
	flat, err := LowerFlat(context.Background(), mem, ba.alloc, ts, vals)
	if err != nil {
		t.Fatalf("LowerFlat: %v", err)
	}
	got, err := LiftFlat(mem, ts, flat)
	if err != nil {
		t.Fatalf("LiftFlat: %v", err)
	}
	if !reflect.DeepEqual(got, vals) {
		t.Errorf("mismatch:\n got %#v\nwant %#v", got, vals)
	}
}

func TestStoreErrors(t *testing.T) {
	mem := newFakeMemory(1 << 16)
	ba := newBumpAlloc(4096)
	ctx := context.Background()

	tests := []struct {
		name    string
		t       Type
		v       any
		errPart string
	}{
		{"wrong-primitive", U32, "nope", "bad value"},
		{"wrong-record", Record(String), "nope", "expected []any"},
		{"record-arity", Record(String, U32), []any{"x"}, "2 fields, got 1"},
		{"enum-range", Enum(3), uint32(3), "out of range"},
		{"variant-case-range", Variant(nil, nil), Var{Case: 5}, "out of range"},
		{"opt-type", Option(String), "not-an-opt", "expected abi.Opt"},
		{"res-type", Result(nil, String), 42, "expected abi.Res"},
		{"bytes-type", List(U8), []any{uint8(1)}, "expected []byte"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Store(ctx, mem, ba.alloc, tc.t, 64, tc.v)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.errPart) {
				t.Errorf("error %q does not contain %q", err, tc.errPart)
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	mem := newFakeMemory(64)

	// Truncated memory: string header points beyond memory.
	if !mem.WriteUint32Le(0, 1<<20) || !mem.WriteUint32Le(4, 10) {
		t.Fatal("setup failed")
	}
	if _, err := Load(mem, String, 0); err == nil {
		t.Error("expected out-of-range string read to fail")
	}

	// Enum discriminant out of range.
	if !writeByte(mem, 16, 9) {
		t.Fatal("setup failed")
	}
	if _, err := Load(mem, Enum(3), 16); err == nil {
		t.Error("expected out-of-range enum discriminant to fail")
	}

	// Variant discriminant out of range.
	if _, err := Load(mem, Variant(nil, String), 16); err == nil {
		t.Error("expected out-of-range variant discriminant to fail")
	}

	// Read entirely outside memory.
	if _, err := Load(mem, U64, 1<<20); err == nil {
		t.Error("expected out-of-range u64 read to fail")
	}
}

func TestResourceTables(t *testing.T) {
	tabs := NewResourceTables()
	ta := tabs.Table("lifecycle#instance")
	tb := tabs.Table("fs#file")
	if ta == tb {
		t.Fatal("distinct keys must have distinct tables")
	}
	if tabs.Table("lifecycle#instance") != ta {
		t.Fatal("same key must return same table")
	}

	h1 := ta.New(100)
	h2 := ta.New(200)
	if h1 == 0 || h2 == 0 {
		t.Fatal("handles must never be 0")
	}
	if h1 == h2 {
		t.Fatal("handles must be unique")
	}
	if rep, ok := ta.Rep(h1); !ok || rep != 100 {
		t.Fatalf("Rep(h1) = %d,%v; want 100,true", rep, ok)
	}
	if rep, ok := ta.Remove(h2); !ok || rep != 200 {
		t.Fatalf("Remove(h2) = %d,%v; want 200,true", rep, ok)
	}
	if _, ok := ta.Rep(h2); ok {
		t.Fatal("h2 must be gone after Remove")
	}
	if ta.Len() != 1 {
		t.Fatalf("Len = %d, want 1", ta.Len())
	}

	// Context plumbing.
	ctx := WithTables(context.Background(), tabs)
	if TablesFromContext(ctx) != tabs {
		t.Fatal("TablesFromContext must return the attached tables")
	}
	if TablesFromContext(context.Background()) != nil {
		t.Fatal("TablesFromContext on empty ctx must be nil")
	}
}
