package contrib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/elee1766/caddy-wit/pkg/runtime"
)

func TestRateLimitPlugin(t *testing.T) {
	ctx := context.Background()
	rt, err := runtime.New(ctx)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.CompilePlugin(ctx, loadWasm(t, "contrib/http/ratelimit/plugin.wasm"))
	if err != nil {
		t.Fatalf("CompilePlugin: %v", err)
	}

	kv := runtime.NewKVStore()
	defer kv.Close()

	env := &runtime.Env{
		Logger: zaptest.NewLogger(t),
		KV:     kv,
	}
	mod, err := plugin.Instantiate(ctx, env)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer mod.Close(ctx)

	cfg := `{
		"requests_per_window": 3,
		"window_seconds": 60,
		"status_code": 429
	}`
	inst, err := mod.Provision(ctx, "http.handlers.rate_limit", cfg)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	t.Run("3 requests ok then 4th rejected", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://example.test/data", nil)
			req.RemoteAddr = "10.0.0.1:1234"

			scope := &runtime.HTTPScope{
				W: rec, R: req,
				Next: func(w http.ResponseWriter, r *http.Request) error {
					w.WriteHeader(http.StatusOK)
					return nil
				},
			}
			if err := inst.ServeHTTP(ctx, scope); err != nil {
				t.Fatalf("request %d: ServeHTTP: %v", i+1, err)
			}
			if got := rec.Header().Get("X-RateLimit-Limit"); got != "3" {
				t.Errorf("request %d: X-RateLimit-Limit = %q, want 3", i+1, got)
			}
		}

		// 4th request should be rejected
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/data", nil)
		req.RemoteAddr = "10.0.0.1:1234"

		nextCalled := false
		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				nextCalled = true
				return nil
			},
		}
		err := inst.ServeHTTP(ctx, scope)
		if err == nil {
			t.Fatal("4th request should have returned error")
		}
		pe, ok := err.(*runtime.PluginError)
		if !ok {
			t.Fatalf("expected *PluginError, got %T: %v", err, err)
		}
		if pe.Status != 429 {
			t.Errorf("status = %d, want 429", pe.Status)
		}
		if nextCalled {
			t.Error("next must NOT be called when rate limited")
		}
		if got := rec.Header().Get("Retry-After"); got != "60" {
			t.Errorf("Retry-After = %q, want 60", got)
		}
	})

	t.Run("different IPs are independent", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/data", nil)
		req.RemoteAddr = "10.0.0.2:5678"

		nextCalled := false
		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
				return nil
			},
		}
		if err := inst.ServeHTTP(ctx, scope); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if !nextCalled {
			t.Error("next should be called for different IP")
		}
		if got := rec.Header().Get("X-RateLimit-Remaining"); got != "2" {
			t.Errorf("X-RateLimit-Remaining = %q, want 2", got)
		}
	})

	if err := inst.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}
