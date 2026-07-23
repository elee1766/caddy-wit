//go:build wasm

package hostkv

import (
	"go.bytecodealliance.org/cm"

	hostkv "github.com/elee1766/caddy-wit/sdk/go/gen/caddy/plugin/host-kv"
)

// Get retrieves a value by key. Returns nil if absent or expired.
func Get(key string) []byte {
	r := hostkv.Get(key)
	if r.None() {
		return nil
	}
	return r.Some().Slice()
}

// Set stores a key-value pair with optional TTL in milliseconds.
func Set(key string, value []byte, ttlMs *uint64) {
	ttl := cm.None[uint64]()
	if ttlMs != nil {
		ttl = cm.Some(*ttlMs)
	}
	hostkv.Set(key, cm.ToList(value), ttl)
}

// Delete removes a key. No-op if absent.
func Delete(key string) {
	hostkv.Delete(key)
}

// Increment atomically increments a counter. Creates with value delta if
// absent. TTL applies only on creation. Returns value after incrementing.
func Increment(key string, delta int64, ttlMs *uint64) int64 {
	ttl := cm.None[uint64]()
	if ttlMs != nil {
		ttl = cm.Some(*ttlMs)
	}
	return hostkv.Increment(key, delta, ttl)
}

// Exists checks existence without reading the value.
func Exists(key string) bool {
	return hostkv.Exists(key)
}
