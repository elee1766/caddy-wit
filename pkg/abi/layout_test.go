package abi

import (
	"reflect"
	"testing"

	"github.com/tetratelabs/wazero/api"
)

const (
	i32 = api.ValueTypeI32
	i64 = api.ValueTypeI64
	f32 = api.ValueTypeF32
	f64 = api.ValueTypeF64
)

// TestLayouts pins size/align/flat for the shapes used by the caddy:plugin
// WIT package. The expected values were produced by wasm-tools (see the
// resolved wit JSON) and must never drift.
func TestLayouts(t *testing.T) {
	// Shapes from wit/types.wit and friends.
	pluginError := Record(String, Option(U16))
	keyInfo := Record(String, S64, S64, Bool)
	event := Record(String, String, S64, String, String)
	fileInfo := Record(String, U64, U32, S64, Bool)
	moduleDecl := Record(String, Option(String))
	token := Record(String, U32, String)

	tests := []struct {
		name  string
		t     Type
		size  uint32
		align uint32
		flat  []api.ValueType
	}{
		{"bool", Bool, 1, 1, []api.ValueType{i32}},
		{"u16", U16, 2, 2, []api.ValueType{i32}},
		{"u64", U64, 8, 8, []api.ValueType{i64}},
		{"s64", S64, 8, 8, []api.ValueType{i64}},
		{"f32", F32, 4, 4, []api.ValueType{f32}},
		{"f64", F64, 8, 8, []api.ValueType{f64}},
		{"string", String, 8, 4, []api.ValueType{i32, i32}},
		{"handle", Handle, 4, 4, []api.ValueType{i32}},
		{"enum4", Enum(4), 1, 1, []api.ValueType{i32}},
		{"enum300", Enum(300), 2, 2, []api.ValueType{i32}},
		{"list<u8>", List(U8), 8, 4, []api.ValueType{i32, i32}},
		{"list<string>", List(String), 8, 4, []api.ValueType{i32, i32}},
		{"empty-record", Record(), 0, 1, nil},

		// option<u16>: disc u8 + payload at align 2 => size 4 align 2.
		{"option<u16>", Option(U16), 4, 2, []api.ValueType{i32, i32}},
		// option<string>: disc u8, payload at 4 => size 12 align 4.
		{"option<string>", Option(String), 12, 4, []api.ValueType{i32, i32, i32}},
		// result<_,string>: disc u8, payload string at 4 => 12/4.
		{"result<_,string>", Result(nil, String), 12, 4, []api.ValueType{i32, i32, i32}},
		// result<u64,string>: joined flats i64+i32 -> [i32 i64 i32].
		{"result<u64,string>", Result(U64, String), 16, 8, []api.ValueType{i32, i64, i32}},
		// result<bool,string>.
		{"result<bool,string>", Result(Bool, String), 12, 4, []api.ValueType{i32, i32, i32}},

		// plugin-error record { message: string, status: option<u16> }
		// wasm-tools: size=12 align=4 flat=[ptr u32 u32 u32].
		{"plugin-error", pluginError, 12, 4, []api.ValueType{i32, i32, i32, i32}},
		// key-info { key: string, modified: s64, size: s64, terminal: bool }
		// wasm-tools: size=32 align=8.
		{"key-info", keyInfo, 32, 8, []api.ValueType{i32, i32, i64, i64, i32}},
		// event { id, name: string, timestamp: s64, origin, data: string }
		// wasm-tools: size=40 align=8.
		{"event", event, 40, 8, []api.ValueType{i32, i32, i32, i32, i64, i32, i32, i32, i32}},
		// file-info { name: string, size: u64, mode: u32, mod-time: s64, dir: bool }
		{"file-info", fileInfo, 40, 8, []api.ValueType{i32, i32, i64, i32, i64, i32}},
		// module-decl { id: string, docs: option<string> }
		// wasm-tools: size=20 align=4.
		{"module-decl", moduleDecl, 20, 4, []api.ValueType{i32, i32, i32, i32, i32}},
		// plugin-info { name: string, version: option<string>, modules: list }
		// wasm-tools: size=28 align=4.
		{"plugin-info", Record(String, Option(String), List(moduleDecl)), 28, 4,
			[]api.ValueType{i32, i32, i32, i32, i32, i32, i32}},
		// issued-certificate { certificate-pem: list<u8>, metadata: option<string> }
		// wasm-tools: size=20 align=4.
		{"issued-certificate", Record(List(U8), Option(String)), 20, 4,
			[]api.ValueType{i32, i32, i32, i32, i32}},
		// certificate-key-pair { certificate-pem, key-pem: list<u8>, tags: list<string> }
		// wasm-tools: size=24 align=4.
		{"certificate-key-pair", Record(List(U8), List(U8), List(String)), 24, 4,
			[]api.ValueType{i32, i32, i32, i32, i32, i32}},
		// token { file: string, line: u32, text: string } => 8+4+pad? text align4 => 8,12..20 => 20/4.
		{"token", token, 20, 4, []api.ValueType{i32, i32, i32, i32, i32}},

		// result<plugin-error payload as err>.
		{"result<_,plugin-error>", Result(nil, pluginError), 16, 4, []api.ValueType{i32, i32, i32, i32, i32}},
		// variant handler-error { aborted, message(string) }.
		{"handler-error", Variant(nil, String), 12, 4, []api.ValueType{i32, i32, i32}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.t.Size(); got != tc.size {
				t.Errorf("Size() = %d, want %d", got, tc.size)
			}
			if got := tc.t.Align(); got != tc.align {
				t.Errorf("Align() = %d, want %d", got, tc.align)
			}
			if got := tc.t.Flat(); !reflect.DeepEqual(got, tc.flat) {
				t.Errorf("Flat() = %v, want %v", got, tc.flat)
			}
		})
	}
}

func TestJoin(t *testing.T) {
	tests := []struct {
		a, b, want api.ValueType
	}{
		{i32, i32, i32},
		{i64, i64, i64},
		{i32, f32, i32},
		{f32, i32, i32},
		{i32, i64, i64},
		{f32, f64, i64},
		{f64, i32, i64},
		{f32, f32, f32},
	}
	for _, tc := range tests {
		if got := join(tc.a, tc.b); got != tc.want {
			t.Errorf("join(%v,%v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
