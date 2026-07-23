package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/elee1766/caddy-wit/pkg/runtime"
)

// TestHelloBigGoPlugin runs the NATIVE-Go-compiled guest (gc toolchain,
// GOOS=wasip1 -buildmode=c-shared, hand-written canonical ABI with
// scalar-only directive signatures). Its purpose is to prove that big Go
// can produce conforming guests today and that the wit-bindgen-go gap is
// purely code generation. Rebuild with:
//
//	cd examples/hello-biggo && GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o plugin.wasm .
func TestHelloBigGoPlugin(t *testing.T) {
	ctx := context.Background()
	rt, err := runtime.New(ctx)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.CompilePlugin(ctx, loadWasm(t, "examples/hello-biggo/plugin.wasm"))
	if err != nil {
		t.Fatalf("CompilePlugin: %v", err)
	}

	info, err := plugin.Info(ctx)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Name != "hello-biggo" || info.Version != "0.1.0" {
		t.Errorf("info = %+v", info)
	}
	if len(info.Modules) != 1 || info.Modules[0].ID != "http.handlers.wit_hello_biggo" {
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

	inst, err := mod.Provision(ctx, "http.handlers.wit_hello_biggo", `{"message":"hi from gc go"}`)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := inst.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}

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
		if rec.Code != 200 || rec.Body.String() != "hi from gc go" {
			t.Errorf("got %d %q", rec.Code, rec.Body.String())
		}
		if rec.Header().Get("X-Wit-Hello-BigGo") != "1" {
			t.Errorf("header missing: %v", rec.Header())
		}
	})

	t.Run("serve middleware passthrough", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/other", nil)
		nextCalled := false
		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				nextCalled = true
				w.WriteHeader(http.StatusTeapot)
				return nil
			},
		}
		if err := inst.ServeHTTP(ctx, scope); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if !nextCalled {
			t.Fatal("next was not called")
		}
		if rec.Code != http.StatusTeapot {
			t.Errorf("status = %d, want 418", rec.Code)
		}
	})

	if err := inst.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}
