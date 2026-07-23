package gen

// net_dns_test.go asserts the canonical-ABI layouts, core signatures, and
// converter round-trips for the host-http / host-tcp / buffered-response /
// dns-provider additions, cross-checked against the wit-bindgen model dump.

import (
	"reflect"
	"testing"

	"github.com/elee1766/caddy-wit/pkg/abi"
)

func TestNetDNSDescriptorLayouts(t *testing.T) {
	cases := []struct {
		name  string
		t     abi.Type
		size  uint32
		align uint32
		flat  int
	}{
		// dump: dns-record size=32 align=4 flat=[ptr len ptr len ptr len u32 u32 u32]
		{"dns-record", dnsRecordT, 32, 4, 9},
		// dump: request-options size=32 align=8 flat=[u32 u32 u32 u64 u32 u32]
		{"request-options", httpRequestOptionsT, 32, 8, 6},
		// dump: response size=20 align=4 flat=[u32 ptr len ptr len]
		{"response", httpResponseT, 20, 4, 5},
	}
	for _, c := range cases {
		if got := c.t.Size(); got != c.size {
			t.Errorf("%s: size = %d, want %d", c.name, got, c.size)
		}
		if got := c.t.Align(); got != c.align {
			t.Errorf("%s: align = %d, want %d", c.name, got, c.align)
		}
		if got := len(c.t.Flat()); got != c.flat {
			t.Errorf("%s: flat len = %d, want %d", c.name, got, c.flat)
		}
	}
}

// TestNetDNSCoreSigs checks the new FuncTypes against the exact core
// signatures in the model dump.
func TestNetDNSCoreSigs(t *testing.T) {
	hostSigs := []struct {
		name            string
		ft              *abi.FuncType
		params, results int
	}{
		// send: method0,1 url0,1 headers0,1 body0,1 options0..6 result -> 16/0
		{"host-http.send", ftHostHTTPSend, 16, 0},
		// connect: address0,1 timeout-ms0,1 result -> 5/0
		{"connection.connect", ftTCPConnConnect, 5, 0},
		// read: self0 max0 result -> 3/0
		{"connection.read", ftTCPConnRead, 3, 0},
		// write: self0 data0,1 result -> 4/0
		{"connection.write", ftTCPConnWrite, 4, 0},
		// set-deadline-ms: self0 ms0 -> 2/0
		{"connection.set-deadline-ms", ftTCPConnSetDeadlineMS, 2, 0},
		// close: self0 -> 1/0
		{"connection.close", ftTCPConnClose, 1, 0},
		// buffered-response.status: self0 -> result0 -> 1/1
		{"buffered-response.status", ftBufferedResponseStatus, 1, 1},
		// buffered-response.headers: self0 result -> 2/0
		{"buffered-response.headers", ftRequestHeaders, 2, 0},
		// buffered-response.body: self0 result -> 2/0
		{"buffered-response.body", ftBufferedResponseBody, 2, 0},
		// next-buffered: req0 result -> 2/0
		{"next-buffered", ftHTTPNextBuffered, 2, 0},
	}
	for _, c := range hostSigs {
		params, results := c.ft.HostSig()
		if len(params) != c.params || len(results) != c.results {
			t.Errorf("%s: got %d params / %d results, want %d / %d",
				c.name, len(params), len(results), c.params, c.results)
		}
	}

	exportSigs := []struct {
		name            string
		ft              *abi.FuncType
		params, results int
	}{
		// get-records: inst0 zone0,1 -> [retptr] -> 3/1
		{"dns-provider.get-records", ftDNSGetRecords, 3, 1},
		// append/set/delete-records: inst0 zone0,1 records0,1 -> [retptr] -> 5/1
		{"dns-provider.append-records", ftDNSMutateRecords, 5, 1},
	}
	for _, c := range exportSigs {
		params, results := c.ft.ExportSig()
		if len(params) != c.params || len(results) != c.results {
			t.Errorf("%s: got %d params / %d results, want %d / %d",
				c.name, len(params), len(results), c.params, c.results)
		}
	}
}

func u16Ptr(v uint16) *uint16 { return &v }

func TestDNSRecordRoundTrip(t *testing.T) {
	for _, r := range []DNSRecord{
		{RRType: "MX", Name: "@", Value: "mail.example.com.", TTLSeconds: 300, Priority: u16Ptr(10)},
		{RRType: "TXT", Name: "_acme-challenge.www", Value: "token", TTLSeconds: 60}, // Priority absent
	} {
		got, err := dnsRecordFromAny(dnsRecordToAny(r))
		if err != nil {
			t.Fatalf("round trip %+v: %v", r, err)
		}
		if !reflect.DeepEqual(got, r) {
			t.Errorf("round trip: got %+v, want %+v", got, r)
		}
	}
}

func TestDNSRecordsRoundTrip(t *testing.T) {
	recs := []DNSRecord{
		{RRType: "A", Name: "www", Value: "203.0.113.7", TTLSeconds: 3600},
		{RRType: "SRV", Name: "_sip._tcp", Value: "sip.example.com.", TTLSeconds: 120, Priority: u16Ptr(5)},
	}
	got, err := dnsRecordsFromAny(dnsRecordsToAny(recs))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if !reflect.DeepEqual(got, recs) {
		t.Errorf("round trip: got %+v, want %+v", got, recs)
	}
}

func TestDNSRecordFromAnyRejectsBadShapes(t *testing.T) {
	if _, err := dnsRecordFromAny("not a record"); err == nil {
		t.Error("expected error for non-record value")
	}
	if _, err := dnsRecordFromAny([]any{"TXT", "n", "v", uint32(1), abi.SomeVal("not u16")}); err == nil {
		t.Error("expected error for bad priority payload")
	}
	if _, err := dnsRecordsFromAny([]any{[]any{"TXT"}}); err == nil {
		t.Error("expected error for short record")
	}
}

func TestHTTPRequestOptionsRoundTrip(t *testing.T) {
	timeout := uint32(5000)
	maxBytes := uint64(1 << 20)
	follow := false
	for _, o := range []*HTTPRequestOptions{
		nil, // option none
		{},  // some(record) with every field absent
		{TimeoutMS: &timeout, MaxResponseBytes: &maxBytes, FollowRedirects: &follow},
	} {
		got, err := httpRequestOptionsFromAny(httpRequestOptionsToAny(o), "options")
		if err != nil {
			t.Fatalf("round trip %+v: %v", o, err)
		}
		if !reflect.DeepEqual(got, o) {
			t.Errorf("round trip: got %+v, want %+v", got, o)
		}
	}
}

func TestHTTPResponseRoundTrip(t *testing.T) {
	r := HTTPResponse{
		Status:  201,
		Headers: []abi.Pair[string, string]{{V0: "Content-Type", V1: "application/json"}},
		Body:    []byte(`{"ok":true}`),
	}
	got, err := httpResponseFromAny(httpResponseToAny(r))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if !reflect.DeepEqual(got, r) {
		t.Errorf("round trip: got %+v, want %+v", got, r)
	}

	// Nil body lowers to an empty list, not nil.
	wire := httpResponseToAny(HTTPResponse{Status: 204})
	if b, ok := wire[2].([]byte); !ok || b == nil {
		t.Errorf("nil body: got %T %v, want non-nil []byte", wire[2], wire[2])
	}
}
