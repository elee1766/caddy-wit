package runtime

// host_net_test.go covers the host-http and host-tcp implementations on
// hostImpl: permission gating, the happy paths, response-size capping,
// redirect handling, and the connection handle table. No wasm involved.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elee1766/caddy-wit/pkg/abi"
	"github.com/elee1766/caddy-wit/pkg/runtime/gen"
)

// --- host-http ---

func TestHTTPSendPermissionDenied(t *testing.T) {
	h := testHost(&Env{}) // Permissions zero value: no network
	_, err := h.HTTPSend(context.Background(), http.MethodGet, "http://example.invalid/", nil, nil, nil)
	if !errors.Is(err, errHTTPPermission) {
		t.Fatalf("got %v, want errHTTPPermission", err)
	}
	if err.Error() != `permission denied: plugin lacks "http" permission` {
		t.Errorf("message = %q", err.Error())
	}
}

func TestHTTPSendHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("X-Token"); got != "secret" {
			t.Errorf("X-Token = %q", got)
		}
		if got := r.Header.Values("X-Multi"); len(got) != 2 {
			t.Errorf("X-Multi = %v, want 2 values", got)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "ping" {
			t.Errorf("body = %q, want %q", body, "ping")
		}
		w.Header().Set("X-Reply", "pong-header")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("pong"))
	}))
	defer srv.Close()

	h := testHost(&Env{Permissions: Permissions{HTTP: true}})
	headers := []abi.Pair[string, string]{
		{V0: "X-Token", V1: "secret"},
		{V0: "X-Multi", V1: "a"},
		{V0: "X-Multi", V1: "b"},
	}
	resp, err := h.HTTPSend(context.Background(), http.MethodPost, srv.URL, headers, []byte("ping"), nil)
	if err != nil {
		t.Fatalf("HTTPSend: %v", err)
	}
	if resp.Status != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.Status)
	}
	if string(resp.Body) != "pong" {
		t.Errorf("body = %q, want %q", resp.Body, "pong")
	}
	found := false
	for _, p := range resp.Headers {
		if p.V0 == "X-Reply" && p.V1 == "pong-header" {
			found = true
		}
	}
	if !found {
		t.Errorf("headers missing X-Reply: %v", resp.Headers)
	}
}

func TestHTTPSendMaxBytesOverflow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer srv.Close()

	h := testHost(&Env{Permissions: Permissions{HTTP: true}})
	maxBytes := uint64(10)
	opts := &gen.HTTPRequestOptions{MaxResponseBytes: &maxBytes}
	_, err := h.HTTPSend(context.Background(), http.MethodGet, srv.URL, nil, nil, opts)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("got %v, want size-cap error (not truncation)", err)
	}

	// A body exactly at the cap succeeds.
	maxBytes = 100
	resp, err := h.HTTPSend(context.Background(), http.MethodGet, srv.URL, nil, nil, opts)
	if err != nil {
		t.Fatalf("at-cap request: %v", err)
	}
	if len(resp.Body) != 100 {
		t.Errorf("body len = %d, want 100", len(resp.Body))
	}
}

func TestHTTPSendFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/target":
			_, _ = w.Write([]byte("landed"))
		}
	}))
	defer srv.Close()

	h := testHost(&Env{Permissions: Permissions{HTTP: true}})

	// Default: redirects are followed.
	resp, err := h.HTTPSend(context.Background(), http.MethodGet, srv.URL, nil, nil, nil)
	if err != nil {
		t.Fatalf("HTTPSend: %v", err)
	}
	if resp.Status != http.StatusOK || string(resp.Body) != "landed" {
		t.Errorf("followed: status=%d body=%q", resp.Status, resp.Body)
	}

	// follow-redirects=false: the 302 itself is returned.
	follow := false
	resp, err = h.HTTPSend(context.Background(), http.MethodGet, srv.URL, nil, nil,
		&gen.HTTPRequestOptions{FollowRedirects: &follow})
	if err != nil {
		t.Fatalf("HTTPSend: %v", err)
	}
	if resp.Status != http.StatusFound {
		t.Errorf("no-follow: status = %d, want 302", resp.Status)
	}
	found := false
	for _, p := range resp.Headers {
		if p.V0 == "Location" && p.V1 == "/target" {
			found = true
		}
	}
	if !found {
		t.Errorf("no-follow: headers missing Location: %v", resp.Headers)
	}
}

// --- host-tcp ---

func TestTCPPermissionDenied(t *testing.T) {
	h := testHost(&Env{})
	_, err := h.TCPConnect(context.Background(), "127.0.0.1:1", nil)
	if !errors.Is(err, errTCPPermission) {
		t.Fatalf("connect: got %v, want errTCPPermission", err)
	}
	if err.Error() != `permission denied: plugin lacks "tcp" permission` {
		t.Errorf("message = %q", err.Error())
	}
	if _, err := h.TCPRead(context.Background(), 1, 16); !errors.Is(err, errTCPPermission) {
		t.Fatalf("read: got %v, want errTCPPermission", err)
	}
	if _, err := h.TCPWrite(context.Background(), 1, []byte("x")); !errors.Is(err, errTCPPermission) {
		t.Fatalf("write: got %v, want errTCPPermission", err)
	}
}

func TestTCPConnectionLifecycle(t *testing.T) {
	server, client := net.Pipe()
	env := &Env{
		Permissions: Permissions{TCP: true},
		DialTCP: func(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
			if address != "echo.internal:7" {
				t.Errorf("address = %q", address)
			}
			return client, nil
		},
	}
	h := testHost(env)
	ctx := context.Background()

	// Echo one message, then close the server side.
	go func() {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(server, buf); err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if _, err := server.Write(buf); err != nil {
			t.Errorf("server write: %v", err)
		}
		_ = server.Close()
	}()

	handle, err := h.TCPConnect(ctx, "echo.internal:7", nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if handle != 1 {
		t.Errorf("handle = %d, want 1 (handles start at 1)", handle)
	}

	n, err := h.TCPWrite(ctx, handle, []byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("write = (%d, %v), want (5, nil)", n, err)
	}

	pair, err := h.TCPRead(ctx, handle, 1024)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(pair.V0) != "hello" || pair.V1 {
		t.Errorf("read = (%q, eof=%v), want (%q, false)", pair.V0, pair.V1, "hello")
	}

	// Server closed: next read reports EOF.
	pair, err = h.TCPRead(ctx, handle, 1024)
	if err != nil {
		t.Fatalf("read after close: %v", err)
	}
	if !pair.V1 {
		t.Errorf("read after close: eof = false, want true")
	}

	// Close removes the handle; further ops fail with unknown handle.
	h.TCPClose(ctx, handle)
	if _, err := h.TCPRead(ctx, handle, 16); !errors.Is(err, errUnknownTCPConn) {
		t.Errorf("read after close: got %v, want errUnknownTCPConn", err)
	}
	if _, err := h.TCPWrite(ctx, handle, []byte("x")); !errors.Is(err, errUnknownTCPConn) {
		t.Errorf("write after close: got %v, want errUnknownTCPConn", err)
	}
	// Close and drop are idempotent.
	h.TCPClose(ctx, handle)
	h.TCPResourceDrop(ctx, handle)
}

func TestTCPConnectDialError(t *testing.T) {
	env := &Env{
		Permissions: Permissions{TCP: true},
		DialTCP: func(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
			return nil, errors.New("connection refused")
		},
	}
	h := testHost(env)
	if _, err := h.TCPConnect(context.Background(), "nope:1", nil); err == nil {
		t.Fatal("expected dial error")
	}
}

func TestTCPSetDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	env := &Env{
		Permissions: Permissions{TCP: true},
		DialTCP: func(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
			return client, nil
		},
	}
	h := testHost(env)
	ctx := context.Background()

	handle, err := h.TCPConnect(ctx, "x:1", nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	// With a short deadline and no data, the read must fail (not block).
	h.TCPSetDeadlineMS(ctx, handle, 10)
	if _, err := h.TCPRead(ctx, handle, 16); err == nil {
		t.Error("expected deadline error")
	}

	// ms=0 clears the deadline; setting on an unknown handle is a no-op.
	h.TCPSetDeadlineMS(ctx, handle, 0)
	h.TCPSetDeadlineMS(ctx, 999, 10)

	h.TCPResourceDrop(ctx, handle)
}

func TestTCPReadChunkCap(t *testing.T) {
	server, client := net.Pipe()
	env := &Env{
		Permissions: Permissions{TCP: true},
		DialTCP: func(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
			return client, nil
		},
	}
	h := testHost(env)
	ctx := context.Background()

	go func() {
		_, _ = server.Write([]byte("abc"))
		_ = server.Close()
	}()

	handle, err := h.TCPConnect(ctx, "x:1", nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// A huge max must not force a huge allocation; the read still works.
	pair, err := h.TCPRead(ctx, handle, 1<<40)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(pair.V0) != "abc" {
		t.Errorf("read = %q, want %q", pair.V0, "abc")
	}
	h.TCPClose(ctx, handle)
}
