package dnsplugin

import (
	"strings"
	"testing"

	"github.com/elee1766/caddy-wit/sdk/go/caddyfile"
)

// directiveTokens builds a single-line directive segment: the directive
// name followed by its arguments, all on line 1 of a Caddyfile.
func directiveTokens(fields ...string) []caddyfile.Token {
	toks := make([]caddyfile.Token, len(fields))
	for i, f := range fields {
		toks[i] = caddyfile.Token{File: "Caddyfile", Line: 1, Text: f}
	}
	return toks
}

func TestCaddyfileToJSON(t *testing.T) {
	tests := []struct {
		name       string
		tokens     []caddyfile.Token
		defaultKey string
		want       string
		wantErr    string // substring of the expected error
	}{
		{name: "no tokens", tokens: nil, defaultKey: "api_token", wantErr: "unexpected EOF"},
		{name: "empty", tokens: directiveTokens("cloudflare"), defaultKey: "api_token", want: `{}`},
		{name: "single bare arg", tokens: directiveTokens("cloudflare", "XYZ"), defaultKey: "api_token",
			want: `{"api_token":"XYZ"}`},
		{name: "single bare arg custom key", tokens: directiveTokens("cloudflare", "XYZ"), defaultKey: "auth_key",
			want: `{"auth_key":"XYZ"}`},
		{name: "one pair", tokens: directiveTokens("cloudflare", "api_token", "XYZ"), defaultKey: "api_token",
			want: `{"api_token":"XYZ"}`},
		{name: "two pairs", tokens: directiveTokens("cloudflare", "api_token", "a", "zone_token", "b"),
			defaultKey: "api_token", want: `{"api_token":"a","zone_token":"b"}`},
		{name: "odd count", tokens: directiveTokens("cloudflare", "a", "b", "c"), defaultKey: "api_token",
			wantErr: "wrong argument count or unexpected line ending after 'c', at Caddyfile:1"},
		{name: "quoted brace is a value", defaultKey: "api_token",
			tokens: []caddyfile.Token{
				{File: "Caddyfile", Line: 1, Text: "cloudflare"},
				{File: "Caddyfile", Line: 1, Text: "api_token"},
				{File: "Caddyfile", Line: 1, Text: "{", Quoted: true},
			},
			want: `{"api_token":"{"}`},
		{name: "block rejected", defaultKey: "api_token",
			tokens: []caddyfile.Token{
				{File: "Caddyfile", Line: 1, Text: "cloudflare"},
				{File: "Caddyfile", Line: 1, Text: "{"},
				{File: "Caddyfile", Line: 2, Text: "api_token"},
				{File: "Caddyfile", Line: 2, Text: "XYZ"},
				{File: "Caddyfile", Line: 3, Text: "}"},
			},
			wantErr: "blocks are not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CaddyfileToJSON(tt.tokens, tt.defaultKey)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got %q", tt.wantErr, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CaddyfileToJSON: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}
