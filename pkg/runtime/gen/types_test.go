package gen

// types_test.go round-trips every struct through its wire (any) form,
// covering both present and absent optional fields. No wasm involved.

import (
	"reflect"
	"testing"

	"github.com/elee1766/caddy-wit/pkg/abi"
)

func strPtr(s string) *string { return &s }

func TestModuleDeclRoundTrip(t *testing.T) {
	for _, md := range []ModuleDecl{
		{ID: "http.handlers.foo", Docs: strPtr("a handler")},
		{ID: "caddy.fs.bar"}, // Docs and CaddyfileOrder absent
		{
			ID:             "http.handlers.baz",
			Docs:           strPtr("ordered handler"),
			CaddyfileOrder: &CaddyfileOrder{Position: DirectiveBefore, RelativeTo: "respond"},
		},
		{
			ID:             "http.handlers.qux", // Docs absent, order present
			CaddyfileOrder: &CaddyfileOrder{Position: DirectiveAfter, RelativeTo: "header"},
		},
	} {
		got, err := moduleDeclFromAny(moduleDeclToAny(md))
		if err != nil {
			t.Fatalf("round trip %+v: %v", md, err)
		}
		if !reflect.DeepEqual(got, md) {
			t.Errorf("round trip: got %+v, want %+v", got, md)
		}
	}
}

func TestPluginInfoRoundTrip(t *testing.T) {
	for _, pi := range []PluginInfo{
		{
			Name:    "demo",
			Version: strPtr("1.2.3"),
			Modules: []ModuleDecl{
				{ID: "http.handlers.a", Docs: strPtr("d"), CaddyfileOrder: &CaddyfileOrder{Position: DirectiveBefore, RelativeTo: "file_server"}},
				{ID: "http.matchers.b"},
			},
		},
		{Name: "empty", Modules: []ModuleDecl{}}, // Version absent, no modules
	} {
		got, err := pluginInfoFromAny(pluginInfoToAny(pi))
		if err != nil {
			t.Fatalf("round trip %+v: %v", pi, err)
		}
		if !reflect.DeepEqual(got, pi) {
			t.Errorf("round trip: got %+v, want %+v", got, pi)
		}
	}
}

func TestTokenRoundTrip(t *testing.T) {
	for _, tok := range []Token{
		{File: "Caddyfile", Line: 42, Text: "gzip"},
		{File: "Caddyfile", Line: 7, Text: "{", Quoted: true},
	} {
		got, err := tokenFromAny(tokenToAny(tok))
		if err != nil {
			t.Fatalf("round trip %+v: %v", tok, err)
		}
		if got != tok {
			t.Errorf("round trip: got %+v, want %+v", got, tok)
		}
	}
}

func TestTokensToAny(t *testing.T) {
	toks := []Token{{File: "f", Line: 1, Text: "a"}, {File: "f", Line: 2, Text: "b", Quoted: true}}
	wire := tokensToAny(toks)
	if len(wire) != 2 {
		t.Fatalf("got %d elements, want 2", len(wire))
	}
	for i := range toks {
		got, err := tokenFromAny(wire[i])
		if err != nil {
			t.Fatalf("element %d: %v", i, err)
		}
		if got != toks[i] {
			t.Errorf("element %d: got %+v, want %+v", i, got, toks[i])
		}
	}
}

func TestPluginErrorRoundTrip(t *testing.T) {
	status := uint16(404)
	for _, pe := range []PluginError{
		{Message: "not found", Status: &status},
		{Message: "boom"}, // Status absent
	} {
		got, err := pluginErrorFromAny(pluginErrorToAny(pe))
		if err != nil {
			t.Fatalf("round trip %+v: %v", pe, err)
		}
		if !reflect.DeepEqual(got, pe) {
			t.Errorf("round trip: got %+v, want %+v", got, pe)
		}
	}
}

func TestKeyInfoRoundTrip(t *testing.T) {
	ki := KeyInfo{Key: "certs/a", Modified: 1700000000000, Size: 1234, Terminal: true}
	got, err := keyInfoFromAny(keyInfoToAny(ki))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if got != ki {
		t.Errorf("round trip: got %+v, want %+v", got, ki)
	}
}

func TestEventRoundTrip(t *testing.T) {
	ev := Event{
		ID:        "550e8400-e29b-41d4-a716-446655440000",
		Name:      "tls_get_certificate",
		Timestamp: 1700000000123,
		Origin:    "tls",
		Data:      `{"k":"v"}`,
	}
	got, err := eventFromAny(eventToAny(ev))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if got != ev {
		t.Errorf("round trip: got %+v, want %+v", got, ev)
	}
}

func TestFileInfoRoundTrip(t *testing.T) {
	fi := FileInfo{Name: "index.html", Size: 4096, Mode: 0o644, ModTime: 1700000000456, Dir: false}
	got, err := fileInfoFromAny(fileInfoToAny(fi))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if got != fi {
		t.Errorf("round trip: got %+v, want %+v", got, fi)
	}

	fis, err := fileInfosFromAny([]any{fileInfoToAny(fi), fileInfoToAny(fi)})
	if err != nil {
		t.Fatalf("list round trip: %v", err)
	}
	if len(fis) != 2 || fis[0] != fi || fis[1] != fi {
		t.Errorf("list round trip: got %+v", fis)
	}
}

func TestIssuedCertificateRoundTrip(t *testing.T) {
	for _, ic := range []IssuedCertificate{
		{CertificatePEM: []byte("PEM"), Metadata: strPtr(`{"ca":"x"}`)},
		{CertificatePEM: []byte{}}, // Metadata absent
	} {
		got, err := issuedCertificateFromAny(issuedCertificateToAny(ic))
		if err != nil {
			t.Fatalf("round trip %+v: %v", ic, err)
		}
		if !reflect.DeepEqual(got, ic) {
			t.Errorf("round trip: got %+v, want %+v", got, ic)
		}
	}
}

func TestCertificateKeyPairRoundTrip(t *testing.T) {
	p := CertificateKeyPair{
		CertificatePEM: []byte("CERT"),
		KeyPEM:         []byte("KEY"),
		Tags:           []string{"a", "b"},
	}
	got, err := certificateKeyPairFromAny(certificateKeyPairToAny(p))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Errorf("round trip: got %+v, want %+v", got, p)
	}

	pairs, err := certificateKeyPairsFromAny([]any{certificateKeyPairToAny(p)})
	if err != nil {
		t.Fatalf("list round trip: %v", err)
	}
	if len(pairs) != 1 || !reflect.DeepEqual(pairs[0], p) {
		t.Errorf("list round trip: got %+v", pairs)
	}
}

func TestHandlerErrorRoundTrip(t *testing.T) {
	for _, he := range []HandlerError{
		{Tag: HandlerErrorAborted},
		{Tag: HandlerErrorMessage, Message: "bad event"},
	} {
		got, err := handlerErrorFromAny(handlerErrorToAny(he))
		if err != nil {
			t.Fatalf("round trip %+v: %v", he, err)
		}
		if got != he {
			t.Errorf("round trip: got %+v, want %+v", got, he)
		}
	}
}

func TestHandlerErrorFromAnyRejectsBadCase(t *testing.T) {
	if _, err := handlerErrorFromAny(abi.Var{Case: 2}); err == nil {
		t.Error("expected error for out-of-range case")
	}
	if _, err := handlerErrorFromAny("nope"); err == nil {
		t.Error("expected error for non-Var value")
	}
}

func TestPairsRoundTrip(t *testing.T) {
	pairs := []abi.Pair[string, string]{{V0: "k1", V1: "v1"}, {V0: "k2", V1: "v2"}}
	got, err := pairsFromAny(pairsToAny(pairs), "fields")
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if !reflect.DeepEqual(got, pairs) {
		t.Errorf("round trip: got %+v, want %+v", got, pairs)
	}
}

func TestConvertersRejectWrongShapes(t *testing.T) {
	if _, err := moduleDeclFromAny("not a record"); err == nil {
		t.Error("moduleDeclFromAny: expected error")
	}
	if _, err := moduleDeclFromAny([]any{"id"}); err == nil {
		t.Error("moduleDeclFromAny: expected field-count error")
	}
	if _, err := moduleDeclFromAny([]any{"id", abi.None, "not an opt"}); err == nil {
		t.Error("moduleDeclFromAny: expected caddyfile-order opt error")
	}
	if _, err := moduleDeclFromAny([]any{"id", abi.None, abi.SomeVal([]any{uint32(2), "respond"})}); err == nil {
		t.Error("moduleDeclFromAny: expected out-of-range position error")
	}
	if _, err := moduleDeclFromAny([]any{"id", abi.None, abi.SomeVal([]any{uint32(0), 42})}); err == nil {
		t.Error("moduleDeclFromAny: expected relative-to string error")
	}
	if _, err := pluginInfoFromAny([]any{"n", abi.None, "not a list"}); err == nil {
		t.Error("pluginInfoFromAny: expected list error")
	}
	if _, err := pluginErrorFromAny([]any{"m", "not an opt"}); err == nil {
		t.Error("pluginErrorFromAny: expected opt error")
	}
	if _, err := pluginErrorFromAny([]any{"m", abi.SomeVal("not u16")}); err == nil {
		t.Error("pluginErrorFromAny: expected u16 error")
	}
	if _, err := keyInfoFromAny([]any{"k", int64(1), "not s64", true}); err == nil {
		t.Error("keyInfoFromAny: expected s64 error")
	}
	if _, err := fileInfoFromAny([]any{1, uint64(2), uint32(3), int64(4), false}); err == nil {
		t.Error("fileInfoFromAny: expected string error")
	}
	if _, err := issuedCertificateFromAny([]any{"not bytes", abi.None}); err == nil {
		t.Error("issuedCertificateFromAny: expected bytes error")
	}
	if _, err := certificateKeyPairFromAny([]any{[]byte{}, []byte{}, []any{1}}); err == nil {
		t.Error("certificateKeyPairFromAny: expected tag error")
	}
	if _, err := eventFromAny([]any{"i", "n", "not s64", "o", "d"}); err == nil {
		t.Error("eventFromAny: expected s64 error")
	}
	if _, err := tokenFromAny([]any{"f", int32(1), "t"}); err == nil {
		t.Error("tokenFromAny: expected u32 error")
	}
}
