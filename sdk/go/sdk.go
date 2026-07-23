// Package sdk is the root of the caddy-wit Go guest SDK. See the dnsplugin
// package for turning a libdns provider into a caddy-wit DNS plugin, the
// caddyfile package for a native-style Dispenser over the tokens handed to
// config.unmarshal-caddyfile, and hosthttp/cabi for the underlying
// plumbing.
//
// Regenerate the caddy:plugin bindings after WIT changes with:
//
//	go generate .
//
//go:generate go tool wit-bindgen-go generate --world full-plugin --out gen ../../wit
package sdk
