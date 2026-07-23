package contrib

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/elee1766/caddy-wit/pkg/runtime"
)

const testJWTSecret = "test-secret-key-123"

// makeTestJWT builds a valid HS256 JWT for testing.
func makeTestJWT(header, payload, secret string) string {
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64
}

func TestJWTPlugin(t *testing.T) {
	ctx := context.Background()
	rt, err := runtime.New(ctx)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.CompilePlugin(ctx, loadWasm(t, "contrib/http/jwt/plugin.wasm"))
	if err != nil {
		t.Fatalf("CompilePlugin: %v", err)
	}

	env := &runtime.Env{Logger: zaptest.NewLogger(t)}
	mod, err := plugin.Instantiate(ctx, env)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer mod.Close(ctx)

	cfg := `{"secret":"` + testJWTSecret + `"}`
	inst, err := mod.Provision(ctx, "http.handlers.jwt", cfg)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := inst.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	t.Run("valid token passes through", func(t *testing.T) {
		token := makeTestJWT(
			`{"alg":"HS256","typ":"JWT"}`,
			`{"sub":"1234567890","name":"Test User"}`,
			testJWTSecret,
		)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/api", nil)
		req.Header.Set("Authorization", "Bearer "+token)

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
		if got := rec.Header().Get("X-JWT-Valid"); got != "true" {
			t.Errorf("X-JWT-Valid = %q, want true", got)
		}
	})

	t.Run("missing header rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/api", nil)

		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				t.Error("next must not be called")
				return nil
			},
		}
		err := inst.ServeHTTP(ctx, scope)
		if err == nil {
			t.Fatal("expected error for missing header")
		}
		pe, ok := err.(*runtime.PluginError)
		if !ok {
			t.Fatalf("expected *PluginError, got %T: %v", err, err)
		}
		if pe.Status != 401 {
			t.Errorf("status = %d, want 401", pe.Status)
		}
		if !strings.Contains(pe.Message, "missing") {
			t.Errorf("message = %q, want 'missing'", pe.Message)
		}
	})

	t.Run("malformed token rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/api", nil)
		req.Header.Set("Authorization", "Bearer not.a.valid.token.with.too.many.parts")

		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				t.Error("next must not be called")
				return nil
			},
		}
		err := inst.ServeHTTP(ctx, scope)
		if err == nil {
			t.Fatal("expected error for malformed token")
		}
		pe, ok := err.(*runtime.PluginError)
		if !ok {
			t.Fatalf("expected *PluginError, got %T: %v", err, err)
		}
		if pe.Status != 401 {
			t.Errorf("status = %d, want 401", pe.Status)
		}
	})

	t.Run("wrong signature rejected", func(t *testing.T) {
		token := makeTestJWT(
			`{"alg":"HS256","typ":"JWT"}`,
			`{"sub":"1234567890"}`,
			"wrong-secret",
		)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://example.test/api", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		scope := &runtime.HTTPScope{
			W: rec, R: req,
			Next: func(w http.ResponseWriter, r *http.Request) error {
				t.Error("next must not be called")
				return nil
			},
		}
		err := inst.ServeHTTP(ctx, scope)
		if err == nil {
			t.Fatal("expected error for wrong signature")
		}
		pe, ok := err.(*runtime.PluginError)
		if !ok {
			t.Fatalf("expected *PluginError, got %T: %v", err, err)
		}
		if pe.Status != 401 {
			t.Errorf("status = %d, want 401", pe.Status)
		}
		if !strings.Contains(pe.Message, "invalid signature") {
			t.Errorf("message = %q, want 'invalid signature'", pe.Message)
		}
	})

	if err := inst.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}
