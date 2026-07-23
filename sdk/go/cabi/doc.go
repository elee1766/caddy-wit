// Package cabi provides the Canonical ABI allocator export
// (`cabi_realloc`) that every caddy:plugin guest binary must expose so the
// host can place strings and lists into guest linear memory.
//
// wit-bindgen-go relies on go.bytecodealliance.org/x/cabi to wire this up,
// but that package does not export cabi_realloc under TinyGo's wasip1
// target, so the SDK ships its own copy. Adapter packages (dnsplugin)
// blank-import cabi; plugin authors never need to reference it directly.
//
// The implementation is only compiled for wasm targets; on other platforms
// this package is empty, which keeps host-side `go build`/`go test` of the
// SDK working.
package cabi
