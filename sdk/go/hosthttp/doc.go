// Package hosthttp bridges Go's net/http client machinery onto the
// caddy:plugin/host-http import: an http.RoundTripper whose RoundTrip is a
// single synchronous `send` call into the host.
//
// Existing HTTP API clients (like libdns provider packages) work unchanged
// inside the wasm sandbox after
//
//	hosthttp.Install()
//
// which swaps http.DefaultTransport for a Transport. Anything using
// http.DefaultClient / http.DefaultTransport then routes through the host,
// subject to the plugin's "http" permission.
//
// The host-http contract is buffer-oriented (no streaming): request bodies
// are read fully before sending and response bodies arrive fully buffered.
// Host-side defaults apply per request: 30s timeout, 16 MiB response cap,
// redirects followed (max 10 hops). Transport{} keeps all of those
// defaults; set Timeout/MaxResponseBytes to override the first two.
//
// The implementation is only compiled for wasm targets (it links against
// the generated host-http import); on other platforms this package is
// empty so host-side `go build`/`go test` of the SDK work.
package hosthttp
