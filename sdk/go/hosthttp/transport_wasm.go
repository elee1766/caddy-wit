//go:build wasm

package hosthttp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.bytecodealliance.org/cm"

	hosthttpgen "github.com/elee1766/caddy-wit/sdk/go/gen/caddy/plugin/host-http"
)

// Transport is an http.RoundTripper backed by the host's
// caddy:plugin/host-http `send` import. The zero value uses the host
// defaults (30s timeout, 16 MiB response cap, redirects followed).
type Transport struct {
	// Timeout is the total per-request timeout. Zero keeps the host
	// default (30s).
	Timeout time.Duration
	// MaxResponseBytes caps the response body size. Zero keeps the host
	// default (16 MiB).
	MaxResponseBytes uint64
}

// RoundTrip implements http.RoundTripper. The request body (if any) is
// read fully, the request is executed synchronously by the host, and the
// fully-buffered response is returned. Host errors (permission denied,
// timeouts, connection failures) surface as *url.Error like net/http's
// own transport errors.
func (t Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: err}
		}
		body = b
	}

	var headers [][2]string
	for k, vs := range req.Header {
		for _, v := range vs {
			headers = append(headers, [2]string{k, v})
		}
	}
	if req.Host != "" && req.Header.Get("Host") == "" {
		headers = append(headers, [2]string{"Host", req.Host})
	}

	options := cm.None[hosthttpgen.RequestOptions]()
	if t.Timeout > 0 || t.MaxResponseBytes > 0 {
		var o hosthttpgen.RequestOptions
		if t.Timeout > 0 {
			o.TimeoutMs = cm.Some(uint32(t.Timeout.Milliseconds()))
		}
		if t.MaxResponseBytes > 0 {
			o.MaxResponseBytes = cm.Some(t.MaxResponseBytes)
		}
		options = cm.Some(o)
	}

	result := hosthttpgen.Send(req.Method, req.URL.String(),
		cm.ToList(headers), cm.ToList(body), options)
	if result.IsErr() {
		return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: errors.New(*result.Err())}
	}

	r := result.OK()
	header := make(http.Header, r.Headers.Len())
	for _, kv := range r.Headers.Slice() {
		header.Add(kv[0], kv[1])
	}
	respBody := r.Body.Slice()
	return &http.Response{
		StatusCode:    int(r.Status),
		Status:        fmt.Sprintf("%d %s", r.Status, http.StatusText(int(r.Status))),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(respBody)),
		ContentLength: int64(len(respBody)),
		Request:       req,
	}, nil
}

// Install makes the host-http bridge the process-wide default:
// http.DefaultTransport becomes a zero-value Transport, so
// http.DefaultClient (and any client with a nil Transport) transparently
// routes through the host. Redirect following stays host-side with the
// default policy; per-request options are left nil.
//
// http.DefaultClient.Transport is set explicitly too: TinyGo's net/http
// Client.Do only consults c.Transport and never falls back to
// http.DefaultTransport (its nil-Transport path dials through the TinyGo
// netdev, which doesn't exist under wasip1).
func Install() {
	http.DefaultTransport = Transport{}
	http.DefaultClient.Transport = Transport{}
}
