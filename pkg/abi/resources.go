package abi

import "sync"

// ResourceTable maps component-model resource handles to guest
// representation values (reps) for one resource type in one module
// instance. Handles are minted starting at 1; 0 is never a valid handle.
//
// All entries are owned: they are created by the guest's [resource-new]
// builtin (or by the host when it receives an own<T> return value) and
// removed on drop.
type ResourceTable struct {
	mu      sync.Mutex
	next    uint32
	entries map[uint32]uint32
}

// New inserts rep and returns a fresh handle.
func (t *ResourceTable) New(rep uint32) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = make(map[uint32]uint32)
		t.next = 1
	}
	h := t.next
	t.next++
	t.entries[h] = rep
	return h
}

// Rep resolves a handle to its rep.
func (t *ResourceTable) Rep(handle uint32) (uint32, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rep, ok := t.entries[handle]
	return rep, ok
}

// Remove deletes a handle, returning its rep.
func (t *ResourceTable) Remove(handle uint32) (uint32, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rep, ok := t.entries[handle]
	if ok {
		delete(t.entries, handle)
	}
	return rep, ok
}

// Len reports the number of live handles.
func (t *ResourceTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// ResourceTables is a lazily-populated set of ResourceTable values keyed by
// an arbitrary string (conventionally "<interface>#<resource>"). One
// ResourceTables exists per instantiated guest module.
type ResourceTables struct {
	mu     sync.Mutex
	tables map[string]*ResourceTable
}

// NewResourceTables returns an empty table set.
func NewResourceTables() *ResourceTables {
	return &ResourceTables{tables: make(map[string]*ResourceTable)}
}

// Table returns the table for key, creating it if needed.
func (t *ResourceTables) Table(key string) *ResourceTable {
	t.mu.Lock()
	defer t.mu.Unlock()
	tab, ok := t.tables[key]
	if !ok {
		tab = &ResourceTable{}
		t.tables[key] = tab
	}
	return tab
}
