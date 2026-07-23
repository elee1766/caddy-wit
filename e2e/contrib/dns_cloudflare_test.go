package contrib

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/elee1766/caddy-wit/pkg/runtime"
)

// TestDNSCloudflarePlugin runs the TinyGo-built Cloudflare DNS provider
// adapter (sdk/go/dnsplugin over the stock github.com/libdns/cloudflare
// package) against a fake Cloudflare v4 API. Rebuild with:
//
//	cd contrib/dns/cloudflare && \
//	  tinygo build -target=wasip1 -buildmode=c-shared -opt=z -no-debug -o plugin.wasm .
//
// The fake implements exactly the endpoints libdns/cloudflare v0.2.2 calls:
//
//   - GET  /client/v4/zones?name=<zone>              (client.go:130 getZoneInfo)
//   - GET  /client/v4/zones/{z}/dns_records?...      (provider.go:48 GetRecords,
//     client.go:85 getDNSRecords)
//   - POST /client/v4/zones/{z}/dns_records          (client.go:25 createRecord)
//   - DELETE /client/v4/zones/{z}/dns_records/{id}   (provider.go:123 DeleteRecords)
//
// The provider hardcodes https://api.cloudflare.com, so Env.HTTPClient uses
// a rewriting transport that points host-side sends at the fake server.
func TestDNSCloudflarePlugin(t *testing.T) {
	ctx := context.Background()

	fake := newFakeCloudflare(t, "example.com", "zone123")
	ts := httptest.NewServer(fake)
	defer ts.Close()

	rt, err := runtime.New(ctx)
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	defer rt.Close(ctx)

	plugin, err := rt.CompilePlugin(ctx, loadWasm(t, "contrib/dns/cloudflare/plugin.wasm"))
	if err != nil {
		t.Fatalf("CompilePlugin: %v", err)
	}

	if caps := plugin.Capabilities(); !caps[runtime.CapDNSProvider] {
		t.Fatalf("CapDNSProvider missing; capabilities: %v", caps)
	}

	info, err := plugin.Info(ctx)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Name != "dns-cloudflare" {
		t.Errorf("Name = %q, want dns-cloudflare", info.Name)
	}
	if len(info.Modules) != 1 || info.Modules[0].ID != "dns.providers.cloudflare" {
		t.Fatalf("Modules = %+v", info.Modules)
	}
	if got := info.Modules[0].CaddyfileOrder; got != nil {
		t.Errorf("CaddyfileOrder = %+v, want nil (dns providers have no directive order)", got)
	}

	env := &runtime.Env{
		Logger:      zaptest.NewLogger(t),
		Permissions: runtime.Permissions{HTTP: true},
		HTTPClient:  &http.Client{Transport: rewriteTransport{target: ts.URL}},
	}
	mod, err := plugin.Instantiate(ctx, env)
	if err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	defer mod.Close(ctx)

	t.Run("caddyfile unmarshal", func(t *testing.T) {
		// Single-arg syntax: cloudflare <api_token>
		out, err := mod.UnmarshalCaddyfile(ctx, "dns.providers.cloudflare", []runtime.Token{
			{Text: "cloudflare"}, {Text: "tok"},
		})
		if err != nil {
			t.Fatalf("UnmarshalCaddyfile: %v", err)
		}
		if !strings.Contains(out, `"api_token":"tok"`) {
			t.Errorf("config JSON = %s", out)
		}

		// Quoted "{" as single-arg value: cloudflare "{"
		out, err = mod.UnmarshalCaddyfile(ctx, "dns.providers.cloudflare", []runtime.Token{
			{File: "Caddyfile", Line: 1, Text: "cloudflare"},
			{File: "Caddyfile", Line: 1, Text: "{", Quoted: true},
		})
		if err != nil {
			t.Fatalf("UnmarshalCaddyfile(quoted brace): %v", err)
		}
		if !strings.Contains(out, `"api_token":"{"`) {
			t.Errorf("quoted-brace config JSON = %s", out)
		}

		// Unquoted "{" opens a block (native cloudflare syntax).
		// Block syntax: cloudflare { api_token <tok>; zone_token <ztok> }
		blockOut, err := mod.UnmarshalCaddyfile(ctx, "dns.providers.cloudflare", []runtime.Token{
			{File: "Caddyfile", Line: 1, Text: "cloudflare"},
			{File: "Caddyfile", Line: 1, Text: "{"},
			{File: "Caddyfile", Line: 2, Text: "api_token"},
			{File: "Caddyfile", Line: 2, Text: "tok"},
			{File: "Caddyfile", Line: 3, Text: "}"},
		})
		if err != nil {
			t.Fatalf("UnmarshalCaddyfile(block): %v", err)
		}
		if !strings.Contains(blockOut, `"api_token"`) {
			t.Errorf("block config = %s", blockOut)
		}
	})

	inst, err := mod.Provision(ctx, "dns.providers.cloudflare", `{"api_token":"test-token"}`)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := inst.Validate(ctx); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	t.Run("append records", func(t *testing.T) {
		out, err := inst.DNSAppendRecords(ctx, "example.com.", []runtime.DNSRecord{{
			Type:  "TXT",
			Name:  "_acme-challenge",
			Value: "forty-two",
			TTL:   120 * time.Second,
		}})
		if err != nil {
			t.Fatalf("DNSAppendRecords: %v", err)
		}
		if len(out) != 1 {
			t.Fatalf("appended = %+v, want 1 record", out)
		}
		got := out[0]
		if got.Type != "TXT" || got.Name != "_acme-challenge" || got.Value != "forty-two" || got.TTL != 120*time.Second {
			t.Errorf("appended record = %+v", got)
		}

		recs := fake.records()
		if len(recs) != 1 {
			t.Fatalf("fake server has %d records, want 1", len(recs))
		}
		if recs[0].Type != "TXT" || recs[0].Name != "_acme-challenge.example.com" || recs[0].Content != `"forty-two"` || recs[0].TTL != 120 {
			t.Errorf("stored record = %+v", recs[0])
		}
	})

	t.Run("get records round-trip", func(t *testing.T) {
		out, err := inst.DNSGetRecords(ctx, "example.com.")
		if err != nil {
			t.Fatalf("DNSGetRecords: %v", err)
		}
		if len(out) != 1 {
			t.Fatalf("records = %+v, want 1", out)
		}
		got := out[0]
		if got.Type != "TXT" || got.Name != "_acme-challenge" || got.Value != "forty-two" || got.TTL != 120*time.Second {
			t.Errorf("record = %+v", got)
		}
		if got.Priority != nil {
			t.Errorf("TXT record has priority %d", *got.Priority)
		}
	})

	t.Run("delete records", func(t *testing.T) {
		out, err := inst.DNSDeleteRecords(ctx, "example.com.", []runtime.DNSRecord{{
			Type:  "TXT",
			Name:  "_acme-challenge",
			Value: "forty-two",
			TTL:   120 * time.Second,
		}})
		if err != nil {
			t.Fatalf("DNSDeleteRecords: %v", err)
		}
		if len(out) != 1 || out[0].Value != "forty-two" {
			t.Fatalf("deleted = %+v, want the TXT record", out)
		}
		if recs := fake.records(); len(recs) != 0 {
			t.Errorf("fake server still has %d records", len(recs))
		}
	})

	t.Run("auth header seen by API", func(t *testing.T) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if fake.requests == 0 {
			t.Fatal("fake API received no requests")
		}
		for _, auth := range fake.authSeen {
			if auth != "Bearer test-token" {
				t.Errorf("Authorization = %q, want %q", auth, "Bearer test-token")
			}
		}
	})

	t.Run("guest error path", func(t *testing.T) {
		_, err := mod.Provision(ctx, "dns.providers.other", `{}`)
		if err == nil || !strings.Contains(err.Error(), "unknown module") {
			t.Fatalf("expected unknown module error, got %v", err)
		}
	})

	t.Run("permission denied without http grant", func(t *testing.T) {
		mod2, err := plugin.Instantiate(ctx, &runtime.Env{Logger: zaptest.NewLogger(t)})
		if err != nil {
			t.Fatalf("Instantiate: %v", err)
		}
		defer mod2.Close(ctx)
		inst2, err := mod2.Provision(ctx, "dns.providers.cloudflare", `{"api_token":"test-token"}`)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		_, err = inst2.DNSGetRecords(ctx, "example.com.")
		if err == nil || !strings.Contains(err.Error(), "permission") {
			t.Fatalf("expected permission error, got %v", err)
		}
	})

	if err := inst.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}

// rewriteTransport redirects every request to the test server, preserving
// path and query. The libdns/cloudflare provider hardcodes
// https://api.cloudflare.com; the host-side send honors Env.HTTPClient, so
// this is where we intercept.
type rewriteTransport struct {
	target string // httptest server base URL, e.g. http://127.0.0.1:PORT
}

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, err := url.Parse(rt.target)
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.URL.Scheme = u.Scheme
	clone.URL.Host = u.Host
	clone.Host = u.Host
	return http.DefaultTransport.RoundTrip(clone)
}

// cfAPIRecord is the DNS record shape of the fake Cloudflare v4 API
// (subset of the fields libdns/cloudflare v0.2.2 models.go reads/writes).
type cfAPIRecord struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Name     string `json:"name,omitempty"`
	Content  string `json:"content,omitempty"`
	Priority uint16 `json:"priority,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	ZoneID   string `json:"zone_id,omitempty"`
	ZoneName string `json:"zone_name,omitempty"`
}

// fakeCloudflare fakes the slice of the Cloudflare v4 API that
// libdns/cloudflare v0.2.2 uses for GetRecords/AppendRecords/DeleteRecords.
type fakeCloudflare struct {
	t        *testing.T
	zoneName string // without trailing dot, as Cloudflare returns it
	zoneID   string

	mu       sync.Mutex
	recs     []cfAPIRecord
	nextID   int
	requests int
	authSeen []string
}

func newFakeCloudflare(t *testing.T, zoneName, zoneID string) *fakeCloudflare {
	return &fakeCloudflare{t: t, zoneName: zoneName, zoneID: zoneID, nextID: 1}
}

func (f *fakeCloudflare) records() []cfAPIRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]cfAPIRecord, len(f.recs))
	copy(out, f.recs)
	return out
}

func (f *fakeCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
	f.mu.Unlock()

	recordsPath := "/client/v4/zones/" + f.zoneID + "/dns_records"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones":
		// getZoneInfo (client.go:130): GET /zones?name=<zone> — the zone
		// arrives fully qualified (trailing dot); Cloudflare matches it
		// and returns the bare name.
		name := r.URL.Query().Get("name")
		if strings.TrimSuffix(name, ".") != f.zoneName {
			f.writeResult(w, []any{})
			return
		}
		f.writeResult(w, []map[string]any{{"id": f.zoneID, "name": f.zoneName}})

	case r.Method == http.MethodGet && r.URL.Path == recordsPath:
		// GetRecords pagination (provider.go:48) and delete/set lookups
		// (client.go:85), filtered by type/name/content.
		q := r.URL.Query()
		f.mu.Lock()
		var out []cfAPIRecord
		for _, rec := range f.recs {
			if v := q.Get("type"); v != "" && rec.Type != v {
				continue
			}
			if v := q.Get("name"); v != "" && rec.Name != strings.TrimSuffix(v, ".") {
				continue
			}
			if v := q.Get("content.exact"); v != "" && rec.Content != v {
				continue
			}
			if v := q.Get("content.contains"); v != "" && !strings.Contains(rec.Content, v) {
				continue
			}
			out = append(out, rec)
		}
		f.mu.Unlock()
		// result_info must be present: provider.go:63 computes the last
		// page from it before the nil check.
		f.writeEnvelope(w, out, map[string]int{
			"page": 1, "per_page": 100, "count": len(out), "total_count": len(out),
		})

	case r.Method == http.MethodPost && r.URL.Path == recordsPath:
		// createRecord (client.go:25).
		var rec cfAPIRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		rec.ID = fmt.Sprintf("rec%d", f.nextID)
		f.nextID++
		rec.ZoneID = f.zoneID
		rec.ZoneName = f.zoneName
		// Cloudflare canonicalizes names to FQDNs (no trailing dot).
		if rec.Name == "@" || rec.Name == "" {
			rec.Name = f.zoneName
		} else if !strings.HasSuffix(rec.Name, f.zoneName) {
			rec.Name = rec.Name + "." + f.zoneName
		}
		f.recs = append(f.recs, rec)
		f.mu.Unlock()
		f.writeResult(w, rec)

	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, recordsPath+"/"):
		// DeleteRecords (provider.go:123).
		id := strings.TrimPrefix(r.URL.Path, recordsPath+"/")
		f.mu.Lock()
		var deleted *cfAPIRecord
		for i, rec := range f.recs {
			if rec.ID == id {
				d := rec
				deleted = &d
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				break
			}
		}
		f.mu.Unlock()
		if deleted == nil {
			http.Error(w, `{"success":false,"errors":[{"code":81044,"message":"Record not found."}]}`, http.StatusNotFound)
			return
		}
		f.writeResult(w, deleted)

	default:
		f.t.Errorf("fake cloudflare: unexpected request %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	}
}

func (f *fakeCloudflare) writeResult(w http.ResponseWriter, result any) {
	f.writeEnvelope(w, result, nil)
}

func (f *fakeCloudflare) writeEnvelope(w http.ResponseWriter, result any, resultInfo any) {
	env := map[string]any{
		"success": true,
		"errors":  []any{},
		"result":  result,
	}
	if resultInfo != nil {
		env["result_info"] = resultInfo
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(env); err != nil {
		f.t.Errorf("encoding response: %v", err)
	}
}
