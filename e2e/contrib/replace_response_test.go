package contrib

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/elee1766/caddy-wit/pkg/runtime"
)

func TestReplaceResponsePlugin(t *testing.T) {
	ctx := context.Background()
	rt, err := runtime.New(ctx)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.CompilePlugin(ctx, loadWasm(t, "contrib/http/replace-response/plugin.wasm"))
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
		"replacements": [{"search": "foo", "replace": "bar"}],
		"content_types": ["text/plain"]
	}`
	inst, err := mod.Provision(ctx, "http.handlers.replace_response", cfg)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := inst.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	t.Run("replaces in matching content type", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)

		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("hello foo world"))
				return nil
			},
		}
		if err := inst.ServeHTTP(ctx, scope); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		want := "hello bar world"
		if got := rec.Body.String(); got != want {
			t.Errorf("body = %q, want %q", got, want)
		}
		if got := rec.Header().Get("Content-Length"); got != fmt.Sprintf("%d", len(want)) {
			t.Errorf("Content-Length = %q, want %d", got, len(want))
		}
	})

	t.Run("no replacement on non-matching content type", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/bin", nil)

		body := "hello foo world"
		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(body))
				return nil
			},
		}
		if err := inst.ServeHTTP(ctx, scope); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if got := rec.Body.String(); got != body {
			t.Errorf("body = %q, want %q (no replacement expected)", got, body)
		}
	})

	t.Run("multiple replacements in order", func(t *testing.T) {
		multiCfg := `{
			"replacements": [
				{"search": "aaa", "replace": "bbb"},
				{"search": "bbb", "replace": "ccc"}
			],
			"content_types": ["text/plain"]
		}`
		multiInst, err := mod.Provision(ctx, "http.handlers.replace_response", multiCfg)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		defer multiInst.Cleanup(ctx)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/chain", nil)

		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("aaa xyz"))
				return nil
			},
		}
		if err := multiInst.ServeHTTP(ctx, scope); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		// "aaa" -> "bbb" -> "ccc" (second replacement applies to result of first)
		want := "ccc xyz"
		if got := rec.Body.String(); got != want {
			t.Errorf("body = %q, want %q", got, want)
		}
	})

	if err := inst.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}
