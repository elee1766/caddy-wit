package shim

import "github.com/elee1766/caddy-wit/pkg/runtime"

// globalSharedKV is the process-wide shared KV store accessible to all wasm
// plugins (via the "shared:" key prefix in host-kv) and to native Go code
// (via SharedKV()).
//
// It is created once and never closed — its lifetime is the process. Config
// reloads don't clear it (that's the point: shared state persists across
// reloads, unlike per-plugin KV which is cleaned up with the plugin).
var globalSharedKV = runtime.NewKVStore()

// SharedKV returns the global shared KV store. Native Go modules can use
// this to read/write data that wasm plugins access via the "shared:" key
// prefix in host-kv.
//
// Example from Go:
//
//	shim.SharedKV().Set("feature_flags", flagsJSON, nil)
//
// Example from a wasm guest:
//
//	host_kv::get("shared:feature_flags")
func SharedKV() *runtime.KVStore {
	return globalSharedKV
}
