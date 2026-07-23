package runtime

// kv.go implements KVStore: an in-memory, TTL-aware key-value store scoped
// to a single plugin instance but shared across all pool slots (wasm
// instances) of that plugin.

import (
	"encoding/binary"
	"sync"
	"time"
)

// kvEntry is a single value in the store.
type kvEntry struct {
	value     []byte
	expiresAt time.Time // zero = never expires
}

// expired reports whether this entry's TTL has passed.
func (e *kvEntry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

// KVStore is a thread-safe, in-memory key-value store with optional TTL on
// entries. It is designed to be shared across all pool slots (wasm module
// instances) of a single provisioned plugin — unlike guest linear memory
// which is per-slot.
//
// Entries expire lazily: Get/Exists check the expiration on access and
// remove stale entries. There is no background reaper in v1.
type KVStore struct {
	mu      sync.Mutex
	entries map[string]*kvEntry
}

// NewKVStore creates an empty KVStore ready for use.
func NewKVStore() *KVStore {
	return &KVStore{entries: make(map[string]*kvEntry)}
}

// Get retrieves a value by key. Returns nil if absent or expired.
func (s *KVStore) Get(key string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok {
		return nil
	}
	if e.expired(time.Now()) {
		delete(s.entries, key)
		return nil
	}
	// Return a copy to avoid data races on the caller's side.
	out := make([]byte, len(e.value))
	copy(out, e.value)
	return out
}

// Set stores a key-value pair. ttlMs is the time-to-live in milliseconds;
// nil means no expiration.
func (s *KVStore) Set(key string, value []byte, ttlMs *uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := &kvEntry{value: make([]byte, len(value))}
	copy(e.value, value)
	if ttlMs != nil {
		e.expiresAt = time.Now().Add(time.Duration(*ttlMs) * time.Millisecond)
	}
	s.entries[key] = e
}

// Delete removes a key. No-op if absent.
func (s *KVStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
}

// Increment atomically increments a counter stored as int64 little-endian.
// If the key is absent or expired it is created with value=delta. ttlMs
// applies only on creation (existing TTL is preserved on increment).
// Returns the value after incrementing.
func (s *KVStore) Increment(key string, delta int64, ttlMs *uint64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	e, ok := s.entries[key]
	if ok && e.expired(now) {
		delete(s.entries, key)
		ok = false
		e = nil
	}

	if !ok {
		// Create fresh entry.
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(delta))
		ne := &kvEntry{value: buf}
		if ttlMs != nil {
			ne.expiresAt = now.Add(time.Duration(*ttlMs) * time.Millisecond)
		}
		s.entries[key] = ne
		return delta
	}

	// Read existing value as int64.
	var current int64
	if len(e.value) >= 8 {
		current = int64(binary.LittleEndian.Uint64(e.value[:8]))
	}
	current += delta
	if len(e.value) < 8 {
		e.value = make([]byte, 8)
	}
	binary.LittleEndian.PutUint64(e.value[:8], uint64(current))
	return current
}

// Exists checks whether a key is present and not expired.
func (s *KVStore) Exists(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok {
		return false
	}
	if e.expired(time.Now()) {
		delete(s.entries, key)
		return false
	}
	return true
}

// Len returns the number of entries (including possibly-expired ones that
// haven't been lazily reaped yet). Useful for observability.
func (s *KVStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Close clears all entries, releasing memory. Safe to call multiple times.
func (s *KVStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[string]*kvEntry)
}
