package runtime_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/elee1766/caddy-wit/pkg/runtime"
)

const helloWasm = "../../examples/hello-rust/plugin.wasm"

func loadPlugin(t *testing.T) (*runtime.Runtime, *runtime.Plugin) {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(helloWasm))
	if err != nil {
		t.Fatalf("reading wasm: %v", err)
	}
	ctx := context.Background()
	rt, err := runtime.New(ctx)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	plugin, err := rt.CompilePlugin(ctx, b)
	if err != nil {
		rt.Close(ctx)
		t.Fatalf("CompilePlugin: %v", err)
	}
	return rt, plugin
}

func TestPoolBasic(t *testing.T) {
	rt, plugin := loadPlugin(t)
	ctx := context.Background()
	defer rt.Close(ctx)

	env := &runtime.Env{Logger: zaptest.NewLogger(t)}
	pool, err := runtime.NewPool(ctx, plugin, env, "http.handlers.wit_hello", `{"message":"pool"}`, runtime.PoolConfig{
		MinInstances: 2,
		MaxInstances: 2,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)

	if pool.Len() != 2 {
		t.Fatalf("Len = %d, want 2", pool.Len())
	}

	// Get both.
	i1, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get 1: %v", err)
	}
	i2, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get 2: %v", err)
	}

	// Third Get with short timeout should fail.
	shortCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_, err = pool.Get(shortCtx)
	if err == nil {
		t.Fatal("expected error from Get with exhausted pool")
	}

	// Put both back.
	pool.Put(i1)
	pool.Put(i2)

	// Get should succeed again.
	i3, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get after Put: %v", err)
	}
	pool.Put(i3)
}

func TestPoolConcurrency(t *testing.T) {
	rt, plugin := loadPlugin(t)
	ctx := context.Background()
	defer rt.Close(ctx)

	env := &runtime.Env{Logger: zaptest.NewLogger(t)}
	pool, err := runtime.NewPool(ctx, plugin, env, "http.handlers.wit_hello", `{"message":"concurrent"}`, runtime.PoolConfig{
		MinInstances: 2,
		MaxInstances: 4,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)

	var wg sync.WaitGroup
	var errCount atomic.Int64
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inst, err := pool.Get(ctx)
			if err != nil {
				errCount.Add(1)
				return
			}
			// Simulate work: call ServeHTTP.
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://example.test/hello", nil)
			scope := &runtime.HTTPScope{
				W: rec, R: req,
				Next: func(w http.ResponseWriter, r *http.Request) error { return nil },
			}
			_ = inst.ServeHTTP(req.Context(), scope)
			time.Sleep(1 * time.Millisecond)
			pool.Put(inst)
		}()
	}
	wg.Wait()

	if errCount.Load() != 0 {
		t.Fatalf("got %d errors from concurrent Gets", errCount.Load())
	}
	// Pool should not exceed max.
	if pool.Len() > 4 {
		t.Fatalf("Len = %d, want <= 4", pool.Len())
	}
}

func TestPoolClose(t *testing.T) {
	rt, plugin := loadPlugin(t)
	ctx := context.Background()
	defer rt.Close(ctx)

	env := &runtime.Env{Logger: zaptest.NewLogger(t)}
	pool, err := runtime.NewPool(ctx, plugin, env, "http.handlers.wit_hello", `{"message":"close"}`, runtime.PoolConfig{
		MinInstances: 2,
		MaxInstances: 4,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	// Get one, then close the pool.
	inst, err := pool.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if err := pool.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Put after close should not panic.
	pool.Put(inst)

	// Get after close should error.
	_, err = pool.Get(ctx)
	if err == nil {
		t.Fatal("expected error from Get after Close")
	}

	// Double close is safe.
	if err := pool.Close(ctx); err != nil {
		t.Fatalf("double Close: %v", err)
	}
}

func TestPoolGrowsOnDemand(t *testing.T) {
	rt, plugin := loadPlugin(t)
	ctx := context.Background()
	defer rt.Close(ctx)

	env := &runtime.Env{Logger: zaptest.NewLogger(t)}
	pool, err := runtime.NewPool(ctx, plugin, env, "http.handlers.wit_hello", `{"message":"grow"}`, runtime.PoolConfig{
		MinInstances: 1,
		MaxInstances: 8,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)

	if pool.Len() != 1 {
		t.Fatalf("initial Len = %d, want 1", pool.Len())
	}

	// Get 5 concurrently — pool must grow.
	instances := make([]*runtime.Instance, 5)
	for i := range instances {
		inst, err := pool.Get(ctx)
		if err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		instances[i] = inst
	}

	if pool.Len() != 5 {
		t.Fatalf("after growth Len = %d, want 5", pool.Len())
	}

	// Put all back.
	for _, inst := range instances {
		pool.Put(inst)
	}

	// Len stays at 5 (doesn't shrink eagerly).
	if pool.Len() != 5 {
		t.Fatalf("after put-back Len = %d, want 5", pool.Len())
	}
}
