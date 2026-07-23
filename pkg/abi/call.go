package abi

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero/api"
)

// Canonical ABI flattening limits (CanonicalABI.md "flattening").
const (
	MaxFlatParams  = 16
	MaxFlatResults = 1
)

// FuncType describes a component-level function signature. Result may be
// nil for functions with no result.
type FuncType struct {
	Params []Type
	Result Type
}

// flatParams returns the concatenated flat types of all parameters.
func (ft *FuncType) flatParams() []api.ValueType {
	var out []api.ValueType
	for _, p := range ft.Params {
		out = append(out, p.Flat()...)
	}
	return out
}

func (ft *FuncType) flatResults() []api.ValueType {
	if ft.Result == nil {
		return nil
	}
	return ft.Result.Flat()
}

// paramsSpilled reports whether parameters exceed MaxFlatParams and are
// passed indirectly through one pointer to an args record.
func (ft *FuncType) paramsSpilled() bool { return len(ft.flatParams()) > MaxFlatParams }

// resultIndirect reports whether the result exceeds MaxFlatResults and is
// passed through linear memory.
func (ft *FuncType) resultIndirect() bool { return len(ft.flatResults()) > MaxFlatResults }

// paramsRecord returns the parameters as a synthetic record used for the
// spill case.
func (ft *FuncType) paramsRecord() Type { return Record(ft.Params...) }

// ExportSig returns the core-wasm signature of this function when exported
// by the guest: spilled params become one i32 pointer; an indirect result
// becomes an i32 pointer RETURNED by the guest.
func (ft *FuncType) ExportSig() (params, results []api.ValueType) {
	if ft.paramsSpilled() {
		params = []api.ValueType{api.ValueTypeI32}
	} else {
		params = ft.flatParams()
	}
	fr := ft.flatResults()
	switch {
	case len(fr) == 0:
		results = nil
	case len(fr) <= MaxFlatResults:
		results = fr
	default:
		results = []api.ValueType{api.ValueTypeI32}
	}
	return params, results
}

// HostSig returns the core-wasm signature of this function when imported by
// the guest from the host: spilled params become one i32 pointer; an
// indirect result appends a trailing i32 retptr PARAMETER supplied by the
// guest.
func (ft *FuncType) HostSig() (params, results []api.ValueType) {
	if ft.paramsSpilled() {
		params = []api.ValueType{api.ValueTypeI32}
	} else {
		params = append(params, ft.flatParams()...)
	}
	fr := ft.flatResults()
	switch {
	case len(fr) == 0:
		results = nil
	case len(fr) <= MaxFlatResults:
		results = fr
	default:
		params = append(params, api.ValueTypeI32) // retptr
		results = nil
	}
	return params, results
}

// CallExport calls the guest export `name` with component-level args,
// handling lowering, spilling, indirect results, and post-return cleanup.
// The returned value follows the Go value mapping; it is nil when the
// function has no result.
func CallExport(ctx context.Context, mod api.Module, name string, ft *FuncType, args []any) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("abi: panic calling %s: %v", name, r)
		}
	}()

	fn := mod.ExportedFunction(name)
	if fn == nil {
		return nil, fmt.Errorf("abi: guest does not export %q (capability not implemented?)", name)
	}
	if len(args) != len(ft.Params) {
		return nil, fmt.Errorf("abi: %s takes %d params, got %d args", name, len(ft.Params), len(args))
	}
	mem := mod.Memory()
	if mem == nil {
		return nil, fmt.Errorf("abi: guest module has no memory")
	}
	alloc := GuestAlloc(mod)

	var core []uint64
	if ft.paramsSpilled() {
		rec := ft.paramsRecord()
		ptr, aerr := alloc(ctx, rec.Size(), rec.Align())
		if aerr != nil {
			return nil, aerr
		}
		if serr := Store(ctx, mem, alloc, rec, ptr, args); serr != nil {
			return nil, fmt.Errorf("abi: spilling args for %s: %w", name, serr)
		}
		core = []uint64{uint64(ptr)}
	} else {
		var lerr error
		core, lerr = LowerFlat(ctx, mem, alloc, ft.Params, args)
		if lerr != nil {
			return nil, fmt.Errorf("abi: lowering args for %s: %w", name, lerr)
		}
	}

	res, cerr := fn.Call(ctx, core...)
	if cerr != nil {
		return nil, fmt.Errorf("abi: calling %s: %w", name, cerr)
	}

	if ft.Result == nil {
		return nil, nil
	}
	if !ft.resultIndirect() {
		if len(res) != 1 {
			return nil, fmt.Errorf("abi: %s returned %d core values, want 1", name, len(res))
		}
		vals, lerr := LiftFlat(mem, []Type{ft.Result}, res)
		if lerr != nil {
			return nil, fmt.Errorf("abi: lifting result of %s: %w", name, lerr)
		}
		return vals[0], nil
	}

	// Indirect result: the guest returned a pointer to the result area.
	if len(res) != 1 {
		return nil, fmt.Errorf("abi: %s returned %d core values, want 1 (retptr)", name, len(res))
	}
	retptr := uint32(res[0])
	v, lerr := Load(mem, ft.Result, retptr)
	if lerr != nil {
		return nil, fmt.Errorf("abi: loading result of %s: %w", name, lerr)
	}
	// Post-return releases guest-side allocations for the returned value.
	// It must run after we've finished reading the result area.
	if post := mod.ExportedFunction("cabi_post_" + name); post != nil {
		if _, perr := post.Call(ctx, res[0]); perr != nil {
			return nil, fmt.Errorf("abi: post-return for %s: %w", name, perr)
		}
	}
	return v, nil
}

// HostImpl is the Go implementation behind a host import. Returning an
// error traps the guest (host failure); guest-visible failures must be
// encoded in the result value (typically a Res with IsErr set).
type HostImpl func(ctx context.Context, mod api.Module, args []any) (any, error)

// NewHostFunc builds the wazero glue for one host import: it returns the
// GoModuleFunction plus the core param/result types to register on the host
// module builder.
func NewHostFunc(name string, ft *FuncType, impl HostImpl) (api.GoModuleFunc, []api.ValueType, []api.ValueType) {
	coreParams, coreResults := ft.HostSig()
	fn := func(ctx context.Context, mod api.Module, stack []uint64) {
		mem := mod.Memory()
		if mem == nil {
			panic(fmt.Errorf("abi: host func %s: guest module has no memory", name))
		}

		// Lift arguments.
		var args []any
		if ft.paramsSpilled() {
			ptr := uint32(stack[0])
			rec := ft.paramsRecord()
			v, err := Load(mem, rec, ptr)
			if err != nil {
				panic(fmt.Errorf("abi: host func %s: reading spilled args: %w", name, err))
			}
			args = v.([]any)
		} else {
			n := len(ft.flatParams())
			v, err := LiftFlat(mem, ft.Params, stack[:n])
			if err != nil {
				panic(fmt.Errorf("abi: host func %s: lifting args: %w", name, err))
			}
			args = v
		}

		result, err := impl(ctx, mod, args)
		if err != nil {
			panic(fmt.Errorf("abi: host func %s: %w", name, err))
		}

		// Lower the result.
		fr := ft.flatResults()
		switch {
		case len(fr) == 0:
			// no result
		case len(fr) <= MaxFlatResults:
			flat, lerr := LowerFlat(ctx, mem, GuestAlloc(mod), []Type{ft.Result}, []any{result})
			if lerr != nil {
				panic(fmt.Errorf("abi: host func %s: lowering result: %w", name, lerr))
			}
			stack[0] = flat[0]
		default:
			// Indirect: the guest passed a retptr as the trailing param.
			retptr := uint32(stack[len(coreParams)-1])
			if serr := Store(ctx, mem, GuestAlloc(mod), ft.Result, retptr, result); serr != nil {
				panic(fmt.Errorf("abi: host func %s: storing result: %w", name, serr))
			}
		}
	}
	return fn, coreParams, coreResults
}
