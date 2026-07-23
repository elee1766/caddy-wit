// Package gen contains hand-written, typed canonical-ABI bindings for the
// caddy:plugin@0.1.0 WIT package, layered on the interpretive engine in
// github.com/elee1766/caddy-wit/pkg/abi.
//
// It is organized the way a binding generator would emit it:
//
//   - types.go: Go structs mirroring the WIT records/variants, plus private
//     converters between those structs and the engine's untyped value
//     mapping ([]any, abi.Opt, abi.Res, abi.Var).
//   - descriptors.go: abi.Type descriptors and abi.FuncType signature tables
//     for every function in the package.
//   - host.go: the Host interface implemented by the embedding runtime,
//     covering every imported (host-provided) function.
//   - instantiate.go: Instantiate, which registers all host import modules
//     (including the guest-exported-resource builtins) on a wazero runtime.
//   - exports.go: Exports, a typed wrapper over the guest's exported
//     functions.
//
// This file set is a reference implementation: a future `witgen` tool is
// expected to generate an equivalent package directly from
// wit/caddy-plugin.wit.json.
package gen
