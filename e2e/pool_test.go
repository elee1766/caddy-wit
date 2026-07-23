package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/elee1766/caddy-wit/pkg/runtime"
)

// TestPoolConcurrentHTTP exercises the pool under real conditions: 50
// concurrent HTTP requests through the full runtime pipeline using the
// hello-rust plugin.
func TestPoolConcurrentHTTP(t *testing.T) {
	ctx := context.Background()
	rt, err := runtime.New(ctx)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.CompilePlugin(ctx, loadWasm(t, "examples/hello-rust/plugin.wasm"))
	if err != nil {
		t.Fatalf("CompilePlugin: %v", err)
	}

	env := &runtime.Env{Logger: zaptest.NewLogger(t)}
	pool, err := runtime.NewPool(ctx, plugin, env, "http.handlers.wit_hello", `{"message":"pool-e2e"}`, runtime.PoolConfig{
		MinInstances: 4,
		MaxInstances: 16,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close(ctx)

	const numRequests = 50
	var wg sync.WaitGroup
	var errCount atomic.Int64
	var successCount atomic.Int64

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			inst, err := pool.Get(ctx)
			if err != nil {
				errCount.Add(1)
				t.Logf("Get error: %v", err)
				return
			}
			defer pool.Put(inst)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://example.test/hello", nil)
			scope := &runtime.HTTPScope{
				W: rec, R: req,
				Next: func(w http.ResponseWriter, r *http.Request) error {
					return nil
				},
			}

			if err := inst.ServeHTTP(req.Context(), scope); err != nil {
				errCount.Add(1)
				t.Logf("ServeHTTP error: %v", err)
				return
			}

			if rec.Code != 200 {
				errCount.Add(1)
				t.Logf("status = %d, want 200", rec.Code)
				return
			}
			if got := rec.Header().Get("X-Wit-Hello"); got != "1" {
				errCount.Add(1)
				t.Logf("X-Wit-Hello = %q, want 1", got)
				return
			}
			if got := rec.Body.String(); got != "pool-e2e" {
				errCount.Add(1)
				t.Logf("body = %q, want pool-e2e", got)
				return
			}
			successCount.Add(1)
		}()
	}
	wg.Wait()

	if errCount.Load() != 0 {
		t.Fatalf("%d/%d requests failed", errCount.Load(), numRequests)
	}
	if successCount.Load() != numRequests {
		t.Fatalf("only %d/%d requests succeeded", successCount.Load(), numRequests)
	}
	t.Logf("pool served %d concurrent requests, pool size: %d", numRequests, pool.Len())
}
