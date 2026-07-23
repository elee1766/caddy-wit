package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/elee1766/caddy-wit/pkg/runtime"
)

// TestHelloTinyGoPlugin runs the TinyGo-built guest (wasip1 +
// wit-bindgen-go bindings, reactor mode) through the same pipeline as the
// Rust guest. Rebuild with:
//
//	cd examples/hello-tinygo && go generate ./... && \
//	  tinygo build -target=wasip1 -buildmode=c-shared -opt=z -no-debug -o plugin.wasm .
func TestHelloTinyGoPlugin(t *testing.T) {
	ctx := context.Background()
	rt, err := runtime.New(ctx)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.CompilePlugin(ctx, loadWasm(t, "examples/hello-tinygo/plugin.wasm"))
	if err != nil {
		t.Fatalf("CompilePlugin: %v", err)
	}

	info, err := plugin.Info(ctx)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Name != "hello-tinygo" {
		t.Errorf("Name = %q, want hello-tinygo", info.Name)
	}
	if len(info.Modules) != 1 || info.Modules[0].ID != "http.handlers.wit_hello_go" {
		t.Fatalf("Modules = %+v", info.Modules)
	}
	wantOrder := &runtime.DirectiveOrder{Position: "before", RelativeTo: "respond"}
	if got := info.Modules[0].CaddyfileOrder; got == nil || *got != *wantOrder {
		t.Errorf("CaddyfileOrder = %+v, want %+v", got, wantOrder)
	}

	mod, err := plugin.Instantiate(ctx, &runtime.Env{Logger: zaptest.NewLogger(t)})
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer mod.Close(ctx)

	t.Run("caddyfile unmarshal", func(t *testing.T) {
		out, err := mod.UnmarshalCaddyfile(ctx, "http.handlers.wit_hello_go", []runtime.Token{
			{Text: "wit_hello_go"}, {Text: "howdy"}, {Text: "gopher"},
		})
		if err != nil {
			t.Fatalf("UnmarshalCaddyfile: %v", err)
		}
		if out != `{"message":"howdy gopher"}` {
			t.Errorf("config JSON = %s", out)
		}
	})

	inst, err := mod.Provision(ctx, "http.handlers.wit_hello_go", `{"message":"hi from go"}`)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := inst.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	t.Run("guest error path", func(t *testing.T) {
		_, err := mod.Provision(ctx, "http.handlers.other", `{}`)
		if err == nil || !strings.Contains(err.Error(), "unknown module id") {
			t.Fatalf("expected unknown module id error, got %v", err)
		}
	})

	t.Run("serve terminal /hello", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/hello", nil)
		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(http.ResponseWriter, *http.Request) error {
				t.Error("next must not be called")
				return nil
			},
		}
		if err := inst.ServeHTTP(ctx, scope); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if rec.Code != 200 || rec.Body.String() != "hi from go" {
			t.Errorf("got %d %q, want 200 %q", rec.Code, rec.Body.String(), "hi from go")
		}
		if rec.Header().Get("X-Wit-Hello-Go") != "1" {
			t.Errorf("X-Wit-Hello-Go missing; headers: %v", rec.Header())
		}
	})

	t.Run("serve middleware passthrough", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "http://example.test/pass", nil)
		nextCalled := false
		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				nextCalled = true
				if got := r.Header.Get("X-Wit-Saw-Go"); got != "PUT" {
					t.Errorf("X-Wit-Saw-Go = %q, want PUT", got)
				}
				w.WriteHeader(http.StatusAccepted)
				return nil
			},
		}
		if err := inst.ServeHTTP(ctx, scope); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if !nextCalled {
			t.Fatal("next was not called")
		}
		if rec.Code != http.StatusAccepted {
			t.Errorf("status = %d, want 202", rec.Code)
		}
	})

	if err := inst.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}
