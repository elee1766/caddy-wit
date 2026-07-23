package runtime

// buffered_test.go covers the next-buffered recording response writer and
// the buffered-response handle plumbing on hostImpl. No wasm involved.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/elee1766/caddy-wit/pkg/abi"
)

func testHost(env *Env) hostImpl {
	if env == nil {
		env = &Env{}
	}
	return hostImpl{m: &Module{internal: moduleInternal{env: env}}}
}

func TestBufferedRecorderDefaults(t *testing.T) {
	rec := newBufferedRecorder(16)
	br := rec.snapshot()
	if br.status != http.StatusOK {
		t.Errorf("status = %d, want 200", br.status)
	}
	if len(br.headers) != 0 {
		t.Errorf("headers = %v, want empty", br.headers)
	}
	if len(br.body) != 0 {
		t.Errorf("body = %q, want empty", br.body)
	}
}

func TestBufferedRecorderRecords(t *testing.T) {
	rec := newBufferedRecorder(1024)
	rec.Header().Set("X-A", "1")
	rec.Header().Add("X-A", "2")
	rec.WriteHeader(http.StatusTeapot)
	rec.WriteHeader(http.StatusOK) // second WriteHeader must be ignored
	if n, err := rec.Write([]byte("hello ")); err != nil || n != 6 {
		t.Fatalf("Write = (%d, %v), want (6, nil)", n, err)
	}
	if n, err := rec.Write([]byte("world")); err != nil || n != 5 {
		t.Fatalf("Write = (%d, %v), want (5, nil)", n, err)
	}

	br := rec.snapshot()
	if br.status != http.StatusTeapot {
		t.Errorf("status = %d, want %d", br.status, http.StatusTeapot)
	}
	if string(br.body) != "hello world" {
		t.Errorf("body = %q, want %q", br.body, "hello world")
	}
	got := map[string]int{}
	for _, p := range br.headers {
		if p.V0 == "X-A" {
			got[p.V1]++
		}
	}
	if got["1"] != 1 || got["2"] != 1 {
		t.Errorf("headers = %v, want both X-A values", br.headers)
	}
}

func TestBufferedRecorderImplicit200(t *testing.T) {
	rec := newBufferedRecorder(16)
	if _, err := rec.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if br := rec.snapshot(); br.status != http.StatusOK {
		t.Errorf("status = %d, want 200", br.status)
	}
}

func TestBufferedRecorderCap(t *testing.T) {
	rec := newBufferedRecorder(4)
	if _, err := rec.Write([]byte("abcd")); err != nil {
		t.Fatalf("write within cap: %v", err)
	}
	if _, err := rec.Write([]byte("e")); !errors.Is(err, errBufferedResponseTooLarge) {
		t.Fatalf("over-cap write: got %v, want errBufferedResponseTooLarge", err)
	}
	if !rec.overflowed {
		t.Error("overflowed not set")
	}
	if got := rec.body.String(); got != "abcd" {
		t.Errorf("body = %q, want %q (no partial over-cap write)", got, "abcd")
	}
}

func TestNextBufferedNoScope(t *testing.T) {
	h := testHost(nil)
	if _, pe := h.NextBuffered(context.Background(), requestHandle); pe == nil {
		t.Error("expected plugin error without scope")
	}
	// Scope with nil Next also fails.
	ctx := withScope(context.Background(), &HTTPScope{})
	if _, pe := h.NextBuffered(ctx, requestHandle); pe == nil {
		t.Error("expected plugin error with nil Next")
	}
}

func TestNextBufferedSuccessAndAccessors(t *testing.T) {
	h := testHost(nil)
	scope := &HTTPScope{
		Next: func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusAccepted)
			_, err := w.Write([]byte("downstream"))
			return err
		},
	}
	ctx := withScope(context.Background(), scope)

	handle, pe := h.NextBuffered(ctx, requestHandle)
	if pe != nil {
		t.Fatalf("NextBuffered: %v", pe.Message)
	}
	if handle != 1 {
		t.Errorf("handle = %d, want 1 (handles start at 1)", handle)
	}

	if got := h.BufferedResponseStatus(ctx, handle); got != http.StatusAccepted {
		t.Errorf("status = %d, want %d", got, http.StatusAccepted)
	}
	if got := string(h.BufferedResponseBody(ctx, handle)); got != "downstream" {
		t.Errorf("body = %q, want %q", got, "downstream")
	}
	found := false
	for _, p := range h.BufferedResponseHeaders(ctx, handle) {
		if p == (abi.Pair[string, string]{V0: "Content-Type", V1: "text/plain"}) {
			found = true
		}
	}
	if !found {
		t.Errorf("headers missing Content-Type: %v", h.BufferedResponseHeaders(ctx, handle))
	}

	// A second call mints a distinct handle.
	handle2, pe := h.NextBuffered(ctx, requestHandle)
	if pe != nil {
		t.Fatalf("second NextBuffered: %v", pe.Message)
	}
	if handle2 != 2 {
		t.Errorf("second handle = %d, want 2", handle2)
	}

	// Drop removes; accessors then return zero values.
	h.BufferedResponseResourceDrop(ctx, handle)
	if got := h.BufferedResponseStatus(ctx, handle); got != 0 {
		t.Errorf("status after drop = %d, want 0", got)
	}
	if got := h.BufferedResponseBody(ctx, handle); got != nil {
		t.Errorf("body after drop = %v, want nil", got)
	}
	// Dropping again is a no-op.
	h.BufferedResponseResourceDrop(ctx, handle)
}

func TestNextBufferedErrorMapping(t *testing.T) {
	h := testHost(nil)

	// A *PluginError from downstream keeps its status.
	scope := &HTTPScope{
		Next: func(w http.ResponseWriter, r *http.Request) error {
			return &PluginError{Message: "boom", Status: 502}
		},
	}
	_, pe := h.NextBuffered(withScope(context.Background(), scope), requestHandle)
	if pe == nil || pe.Message != "boom" || pe.Status == nil || *pe.Status != 502 {
		t.Errorf("plugin error mapping: got %+v", pe)
	}

	// A generic error becomes a message-only plugin error.
	scope = &HTTPScope{
		Next: func(w http.ResponseWriter, r *http.Request) error {
			return errors.New("generic failure")
		},
	}
	_, pe = h.NextBuffered(withScope(context.Background(), scope), requestHandle)
	if pe == nil || pe.Message != "generic failure" || pe.Status != nil {
		t.Errorf("generic error mapping: got %+v", pe)
	}

	// A downstream handler that overflows the cap but swallows the write
	// error still fails the call.
	scope = &HTTPScope{
		Next: func(w http.ResponseWriter, r *http.Request) error {
			_, _ = w.Write(make([]byte, maxBufferedResponseBytes+1))
			return nil
		},
	}
	_, pe = h.NextBuffered(withScope(context.Background(), scope), requestHandle)
	if pe == nil {
		t.Error("expected plugin error for over-cap downstream response")
	}
}
