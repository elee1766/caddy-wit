// Package hostkv re-exports the caddy:plugin/host-kv import interface for
// use by guest plugins. The underlying generated bindings are internal; this
// package provides the public API.
//
// The implementation is only compiled for wasm targets; on other platforms
// this package is empty so host-side `go build`/`go test` of the SDK work.
package hostkv
