package runtime

import (
	"sync"
	"testing"
	"time"
)

func TestKVStore_GetSetDelete(t *testing.T) {
	kv := NewKVStore()
	defer kv.Close()

	// Get on empty store returns nil.
	if got := kv.Get("missing"); got != nil {
		t.Fatalf("expected nil for missing key, got %v", got)
	}

	// Set and Get.
	kv.Set("hello", []byte("world"), nil)
	if got := kv.Get("hello"); string(got) != "world" {
		t.Fatalf("expected 'world', got %q", got)
	}

	// Overwrite.
	kv.Set("hello", []byte("earth"), nil)
	if got := kv.Get("hello"); string(got) != "earth" {
		t.Fatalf("expected 'earth', got %q", got)
	}

	// Delete.
	kv.Delete("hello")
	if got := kv.Get("hello"); got != nil {
		t.Fatalf("expected nil after delete, got %v", got)
	}

	// Delete on missing key is a no-op.
	kv.Delete("nonexistent")
}

func TestKVStore_TTLExpiry(t *testing.T) {
	kv := NewKVStore()
	defer kv.Close()

	ttl := uint64(50) // 50ms
	kv.Set("ephemeral", []byte("data"), &ttl)

	// Immediately available.
	if got := kv.Get("ephemeral"); string(got) != "data" {
		t.Fatalf("expected 'data', got %q", got)
	}
	if !kv.Exists("ephemeral") {
		t.Fatal("expected Exists=true before TTL")
	}

	// Wait for expiry.
	time.Sleep(80 * time.Millisecond)

	if got := kv.Get("ephemeral"); got != nil {
		t.Fatalf("expected nil after TTL, got %v", got)
	}
	if kv.Exists("ephemeral") {
		t.Fatal("expected Exists=false after TTL")
	}
}

func TestKVStore_Exists(t *testing.T) {
	kv := NewKVStore()
	defer kv.Close()

	if kv.Exists("nope") {
		t.Fatal("expected false for missing key")
	}

	kv.Set("present", []byte{1}, nil)
	if !kv.Exists("present") {
		t.Fatal("expected true for present key")
	}
}

func TestKVStore_Increment(t *testing.T) {
	kv := NewKVStore()
	defer kv.Close()

	// Creates with delta if absent.
	got := kv.Increment("counter", 5, nil)
	if got != 5 {
		t.Fatalf("expected 5, got %d", got)
	}

	// Increments.
	got = kv.Increment("counter", 3, nil)
	if got != 8 {
		t.Fatalf("expected 8, got %d", got)
	}

	// Negative delta.
	got = kv.Increment("counter", -2, nil)
	if got != 6 {
		t.Fatalf("expected 6, got %d", got)
	}

	// TTL only on creation; second increment preserves existing entry.
	ttl := uint64(50)
	got = kv.Increment("counter", 1, &ttl)
	if got != 7 {
		t.Fatalf("expected 7, got %d", got)
	}
	// The TTL should not have been applied since key existed.
	time.Sleep(80 * time.Millisecond)
	if !kv.Exists("counter") {
		t.Fatal("expected counter to still exist (TTL only on creation)")
	}
}

func TestKVStore_IncrementTTLOnCreation(t *testing.T) {
	kv := NewKVStore()
	defer kv.Close()

	ttl := uint64(50)
	kv.Increment("rate", 1, &ttl)

	if !kv.Exists("rate") {
		t.Fatal("expected rate to exist immediately after creation")
	}

	time.Sleep(80 * time.Millisecond)

	// Now expired; next increment should recreate.
	got := kv.Increment("rate", 10, &ttl)
	if got != 10 {
		t.Fatalf("expected 10 (recreated), got %d", got)
	}
}

func TestKVStore_Len(t *testing.T) {
	kv := NewKVStore()
	defer kv.Close()

	if kv.Len() != 0 {
		t.Fatalf("expected 0, got %d", kv.Len())
	}

	kv.Set("a", []byte{1}, nil)
	kv.Set("b", []byte{2}, nil)
	if kv.Len() != 2 {
		t.Fatalf("expected 2, got %d", kv.Len())
	}

	kv.Delete("a")
	if kv.Len() != 1 {
		t.Fatalf("expected 1, got %d", kv.Len())
	}
}

func TestKVStore_Close(t *testing.T) {
	kv := NewKVStore()
	kv.Set("x", []byte("y"), nil)
	kv.Close()

	if kv.Len() != 0 {
		t.Fatal("expected empty store after Close")
	}
	// Should still be usable after close (just empty).
	kv.Set("a", []byte("b"), nil)
	if got := kv.Get("a"); string(got) != "b" {
		t.Fatalf("expected 'b', got %q", got)
	}
}

func TestKVStore_ConcurrentIncrement(t *testing.T) {
	kv := NewKVStore()
	defer kv.Close()

	const goroutines = 100
	const increments = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < increments; j++ {
				kv.Increment("shared", 1, nil)
			}
		}()
	}
	wg.Wait()

	got := kv.Increment("shared", 0, nil)
	expected := int64(goroutines * increments)
	if got != expected {
		t.Fatalf("expected %d, got %d", expected, got)
	}
}

func TestKVStore_ConcurrentMixed(t *testing.T) {
	kv := NewKVStore()
	defer kv.Close()

	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Writers.
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			kv.Set("key", []byte{byte(i)}, nil)
		}(i)
	}
	// Readers.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = kv.Get("key")
		}()
	}
	// Deleters.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			kv.Delete("key")
		}()
	}

	wg.Wait()
}

func TestKVStore_GetReturnsCopy(t *testing.T) {
	kv := NewKVStore()
	defer kv.Close()

	kv.Set("k", []byte("original"), nil)
	got := kv.Get("k")
	// Mutate the returned slice.
	got[0] = 'X'
	// The store's internal value should not be affected.
	if got2 := kv.Get("k"); string(got2) != "original" {
		t.Fatalf("expected 'original', got %q (internal state mutated)", got2)
	}
}
