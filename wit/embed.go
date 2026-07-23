// Package wit embeds the caddy:plugin WIT package — the source of truth for
// the guest interface that caddy-wit plugins compile against.
package wit

import "embed"

// FS contains the caddy:plugin WIT definitions and the resolved JSON form.
//
//go:embed *.wit caddy-plugin.wit.json
var FS embed.FS
