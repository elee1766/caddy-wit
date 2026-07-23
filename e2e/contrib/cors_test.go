package contrib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/elee1766/caddy-wit/pkg/runtime"
)

func TestCorsPlugin(t *testing.T) {
	ctx := context.Background()
	rt, err := runtime.New(ctx)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.CompilePlugin(ctx, loadWasm(t, "contrib/http/cors/plugin.wasm"))
	if err != nil {
		t.Fatalf("CompilePlugin: %v", err)
	}

	env := &runtime.Env{Logger: zaptest.NewLogger(t)}
	mod, err := plugin.Instantiate(ctx, env)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer mod.Close(ctx)

	cfg := `{
		"allowed_origins": ["*"],
		"allowed_methods": ["GET","POST","OPTIONS"],
		"allowed_headers": ["Content-Type","Authorization"],
		"expose_headers": ["X-Custom"],
		"max_age": 3600,
		"allow_credentials": false
	}`
	inst, err := mod.Provision(ctx, "http.handlers.cors", cfg)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := inst.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	t.Run("preflight OPTIONS returns 204 with CORS headers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodOptions, "http://example.test/api", nil)
		req.Header.Set("Origin", "https://app.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")

		nextCalled := false
		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				nextCalled = true
				return nil
			},
		}
		if err := inst.ServeHTTP(ctx, scope); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if nextCalled {
			t.Error("next must NOT be called for preflight")
		}
		if rec.Code != 204 {
			t.Errorf("status = %d, want 204", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("Allow-Origin = %q, want *", got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
			t.Error("Allow-Methods header missing")
		}
		if got := rec.Header().Get("Access-Control-Allow-Headers"); got == "" {
			t.Error("Allow-Headers header missing")
		}
		if got := rec.Header().Get("Access-Control-Max-Age"); got != "3600" {
			t.Errorf("Max-Age = %q, want 3600", got)
		}
		if got := rec.Header().Get("Access-Control-Expose-Headers"); got != "X-Custom" {
			t.Errorf("Expose-Headers = %q, want X-Custom", got)
		}
	})

	t.Run("GET with Origin calls next and adds CORS headers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/data", nil)
		req.Header.Set("Origin", "https://app.example.com")

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
			t.Fatal("next was not called")
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("Allow-Origin = %q, want *", got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
			t.Error("Allow-Methods header missing")
		}
	})

	t.Run("no Origin header passes through without CORS headers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/data", nil)

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
			t.Fatal("next was not called")
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Allow-Origin should be absent, got %q", got)
		}
	})

	t.Run("wildcard + credentials echoes origin not star", func(t *testing.T) {
		// Provision a new instance with credentials enabled.
		credCfg := `{
			"allowed_origins": ["*"],
			"allow_credentials": true
		}`
		credInst, err := mod.Provision(ctx, "http.handlers.cors", credCfg)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		defer credInst.Cleanup(ctx)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/data", nil)
		req.Header.Set("Origin", "https://specific.example.com")

		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusOK)
				return nil
			},
		}
		if err := credInst.ServeHTTP(ctx, scope); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://specific.example.com" {
			t.Errorf("Allow-Origin = %q, want echoed origin", got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Errorf("Allow-Credentials = %q, want true", got)
		}
	})

	if err := inst.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}
