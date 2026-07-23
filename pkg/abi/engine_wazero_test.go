package abi

import (
	"context"
	_ "embed"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed testdata/engine_test.wasm
var engineTestWasm []byte

// TestEngineAgainstWazero runs the engine against a real wazero guest,
// covering: direct flat calls, indirect (retptr) export results with guest
// allocation, and host imports that allocate in guest memory reentrantly
// via cabi_realloc.
func TestEngineAgainstWazero(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	// Host module "test" with upper(string) -> string.
	upperType := &FuncType{Params: []Type{String}, Result: String}
	fn, params, results := NewHostFunc("upper", upperType, func(ctx context.Context, mod api.Module, args []any) (any, error) {
		return strings.ToUpper(args[0].(string)), nil
	})
	// Sanity-check the computed host signature: (i32,i32) string + i32 retptr.
	wantParams := []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}
	if len(params) != len(wantParams) || len(results) != 0 {
		t.Fatalf("HostSig = (%v, %v), want (%v, [])", params, results, wantParams)
	}
	_, err := rt.NewHostModuleBuilder("test").
		NewFunctionBuilder().
		WithGoModuleFunction(fn, params, results).
		Export("upper").
		Instantiate(ctx)
	if err != nil {
		t.Fatalf("instantiating host module: %v", err)
	}

	mod, err := rt.Instantiate(ctx, engineTestWasm)
	if err != nil {
		t.Fatalf("instantiating guest: %v", err)
	}

	t.Run("direct flat result", func(t *testing.T) {
		ft := &FuncType{Params: []Type{U32, U32}, Result: U32}
		got, err := CallExport(ctx, mod, "add", ft, []any{uint32(40), uint32(2)})
		if err != nil {
			t.Fatalf("CallExport(add): %v", err)
		}
		if got != uint32(42) {
			t.Errorf("add = %v, want 42", got)
		}
	})

	t.Run("string lowering and indirect result", func(t *testing.T) {
		ft := &FuncType{Params: []Type{String}, Result: String}
		in := "héllo wörld 🎉"
		got, err := CallExport(ctx, mod, "echo", ft, []any{in})
		if err != nil {
			t.Fatalf("CallExport(echo): %v", err)
		}
		if got != in {
			t.Errorf("echo = %q, want %q", got, in)
		}
	})

	t.Run("host import with reentrant guest alloc", func(t *testing.T) {
		ft := &FuncType{Params: []Type{String}, Result: String}
		got, err := CallExport(ctx, mod, "call-upper", ft, []any{"héllo caddy"})
		if err != nil {
			t.Fatalf("CallExport(call-upper): %v", err)
		}
		if got != "HÉLLO CADDY" {
			t.Errorf("call-upper = %q, want %q", got, "HÉLLO CADDY")
		}
	})

	t.Run("missing export", func(t *testing.T) {
		ft := &FuncType{Params: nil, Result: nil}
		_, err := CallExport(ctx, mod, "nope", ft, nil)
		if err == nil || !strings.Contains(err.Error(), "does not export") {
			t.Errorf("expected missing-export error, got %v", err)
		}
	})
}
