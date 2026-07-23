package dnsplugin

import (
	"encoding/json"

	"go.bytecodealliance.org/cm"

	"github.com/elee1766/caddy-wit/sdk/go/caddyfile"
	"github.com/elee1766/caddy-wit/sdk/go/gen/caddy/plugin/config"
)

// TokensFromWire lifts generated binding tokens into caddyfile.Token so
// the mapping logic can use the native-style caddyfile.Dispenser.
func TokensFromWire(tokens cm.List[config.Token]) []caddyfile.Token {
	in := tokens.Slice()
	out := make([]caddyfile.Token, len(in))
	for i, t := range in {
		out[i] = caddyfile.Token{
			File:   t.File,
			Line:   int(t.Line),
			Text:   t.Text,
			Quoted: t.Quoted,
		}
	}
	return out
}

// CaddyfileToJSON implements the generic Caddyfile mapping used for
// config.unmarshal-caddyfile. tokens is the directive's whole segment,
// starting with the directive name itself. Rules for the same-line
// arguments after the directive name:
//
//   - no arguments        -> {}
//   - one argument        -> {<defaultKey>: <arg>}   (e.g. `cloudflare XYZ`)
//   - 2n arguments        -> key/value pairs         (e.g. `cloudflare api_token XYZ`)
//   - any other odd count -> ArgErr-style error with file:line position
//
// Anything beyond the directive line (a block or extra lines) is a syntax
// error. Output is deterministic (json.Marshal of map[string]string sorts
// keys).
func CaddyfileToJSON(tokens []caddyfile.Token, defaultKey string) (string, error) {
	d := caddyfile.NewDispenser(tokens)
	m := map[string]string{}
	if !d.Next() {
		return "", d.EOFErr()
	}
	args := d.RemainingArgs()
	switch {
	case len(args) == 0:
		// zero-config provider (credentials from elsewhere)
	case len(args) == 1:
		m[defaultKey] = args[0]
	case len(args)%2 == 0:
		for i := 0; i < len(args); i += 2 {
			m[args[i]] = args[i+1]
		}
	default:
		return "", d.ArgErr()
	}
	if d.NextBlock(0) {
		return "", d.Err("blocks are not supported; use key/value arguments on the directive line")
	}
	if d.Next() {
		return "", d.SyntaxErr("end of directive")
	}
	out, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
