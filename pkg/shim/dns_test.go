package shim

// Pure-function tests for the libdns <-> runtime.DNSRecord conversions.
// The DNSProvider shim itself is not exercised here: it needs a live wasm
// instance, and caddy.RegisterModule is process-global, so shim types are
// covered by integration tests instead.

import (
	"reflect"
	"testing"
	"time"

	"github.com/elee1766/caddy-wit/pkg/runtime"
	"github.com/libdns/libdns"
)

func u16(v uint16) *uint16 { return &v }

func TestFromLibdnsRecord(t *testing.T) {
	tests := []struct {
		name string
		in   libdns.Record
		want runtime.DNSRecord
	}{
		{
			name: "TXT via raw RR (what certmagic's DNS-01 solver sends)",
			in: libdns.RR{
				Type: "TXT",
				Name: "_acme-challenge.www",
				Data: "token-value",
				TTL:  5 * time.Minute,
			},
			want: runtime.DNSRecord{
				Type:  "TXT",
				Name:  "_acme-challenge.www",
				Value: "token-value",
				TTL:   5 * time.Minute,
			},
		},
		{
			name: "typed TXT",
			in:   libdns.TXT{Name: "@", TTL: 30 * time.Second, Text: "hello world"},
			want: runtime.DNSRecord{Type: "TXT", Name: "@", Value: "hello world", TTL: 30 * time.Second},
		},
		{
			name: "MX splits leading priority",
			in:   libdns.MX{Name: "@", TTL: time.Hour, Preference: 10, Target: "mail.example.com."},
			want: runtime.DNSRecord{
				Type: "MX", Name: "@", Value: "mail.example.com.",
				TTL: time.Hour, Priority: u16(10),
			},
		},
		{
			name: "SRV splits priority, keeps weight/port/target in value",
			in: libdns.SRV{
				Service: "sip", Transport: "tcp", Name: "@", TTL: time.Minute,
				Priority: 5, Weight: 10, Port: 5060, Target: "sip.example.com.",
			},
			want: runtime.DNSRecord{
				Type: "SRV", Name: "_sip._tcp", Value: "10 5060 sip.example.com.",
				TTL: time.Minute, Priority: u16(5),
			},
		},
		{
			name: "zero-priority MX with empty data stays priority-less",
			in:   libdns.MX{Name: "x"},
			want: runtime.DNSRecord{Type: "MX", Name: "x"},
		},
		{
			name: "A record has no priority handling",
			in:   libdns.RR{Type: "A", Name: "www", Data: "192.0.2.1", TTL: time.Minute},
			want: runtime.DNSRecord{Type: "A", Name: "www", Value: "192.0.2.1", TTL: time.Minute},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fromLibdnsRecord(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fromLibdnsRecord(%+v) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestToLibdnsRecord(t *testing.T) {
	tests := []struct {
		name string
		in   runtime.DNSRecord
		want libdns.RR // compared via .RR()
		typ  any       // expected concrete type, nil to skip
	}{
		{
			name: "TXT",
			in:   runtime.DNSRecord{Type: "TXT", Name: "_acme-challenge", Value: "tok", TTL: 2 * time.Minute},
			want: libdns.RR{Type: "TXT", Name: "_acme-challenge", Data: "tok", TTL: 2 * time.Minute},
			typ:  libdns.TXT{},
		},
		{
			name: "MX rejoins priority into RDATA",
			in:   runtime.DNSRecord{Type: "MX", Name: "@", Value: "mail.example.com.", TTL: time.Hour, Priority: u16(10)},
			want: libdns.RR{Type: "MX", Name: "@", Data: "10 mail.example.com.", TTL: time.Hour},
			typ:  libdns.MX{},
		},
		{
			name: "nil priority leaves value untouched",
			in:   runtime.DNSRecord{Type: "A", Name: "www", Value: "192.0.2.1"},
			want: libdns.RR{Type: "A", Name: "www", Data: "192.0.2.1"},
			typ:  libdns.Address{},
		},
		{
			name: "zero (non-nil) priority is still prepended",
			in:   runtime.DNSRecord{Type: "MX", Name: "@", Value: "mail.example.com.", Priority: u16(0)},
			want: libdns.RR{Type: "MX", Name: "@", Data: "0 mail.example.com."},
			typ:  libdns.MX{},
		},
		{
			name: "priority with empty value",
			in:   runtime.DNSRecord{Type: "MX", Name: "@", Priority: u16(7)},
			want: libdns.RR{Type: "MX", Name: "@", Data: "7"},
			typ:  nil, // "7" alone doesn't parse as MX; degrades to RR
		},
		{
			name: "unknown type passes through as RR",
			in:   runtime.DNSRecord{Type: "NAPTR", Name: "x", Value: "whatever"},
			want: libdns.RR{Type: "NAPTR", Name: "x", Data: "whatever"},
			typ:  libdns.RR{},
		},
		{
			name: "malformed known type degrades to RR instead of failing",
			in:   runtime.DNSRecord{Type: "A", Name: "www", Value: "not-an-ip"},
			want: libdns.RR{Type: "A", Name: "www", Data: "not-an-ip"},
			typ:  libdns.RR{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toLibdnsRecord(tt.in)
			if rr := got.RR(); !reflect.DeepEqual(rr, tt.want) {
				t.Errorf("toLibdnsRecord(%+v).RR() = %+v, want %+v", tt.in, rr, tt.want)
			}
			if tt.typ != nil && reflect.TypeOf(got) != reflect.TypeOf(tt.typ) {
				t.Errorf("toLibdnsRecord(%+v) concrete type = %T, want %T", tt.in, got, tt.typ)
			}
		})
	}
}

// TestDNSRecordRoundTrip checks host->guest->host fidelity at the RR
// level: converting a libdns record to the WIT representation and back
// must preserve name, type, TTL, and RDATA (including the priority).
func TestDNSRecordRoundTrip(t *testing.T) {
	recs := []libdns.Record{
		libdns.RR{Type: "TXT", Name: "_acme-challenge.www", Data: "tok", TTL: 5 * time.Minute},
		libdns.TXT{Name: "@", Text: "v=spf1 -all", TTL: time.Hour},
		libdns.MX{Name: "@", Preference: 20, Target: "mx2.example.com.", TTL: time.Hour},
		libdns.SRV{Service: "xmpp", Transport: "tcp", Name: "@", Priority: 1, Weight: 2, Port: 5222, Target: "x.example.com.", TTL: time.Minute},
		libdns.CNAME{Name: "alias", Target: "canonical.example.com.", TTL: 10 * time.Second},
	}
	for _, rec := range recs {
		want := rec.RR()
		got := toLibdnsRecord(fromLibdnsRecord(rec)).RR()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("round trip of %+v: got RR %+v, want %+v", rec, got, want)
		}
	}
}

// TestDNSRecordRoundTripGuestSide checks guest->host->guest fidelity,
// including the nil-vs-set priority distinction and sub-second TTLs.
func TestDNSRecordRoundTripGuestSide(t *testing.T) {
	recs := []runtime.DNSRecord{
		{Type: "TXT", Name: "_acme-challenge", Value: "tok", TTL: 120 * time.Second},
		{Type: "MX", Name: "@", Value: "mail.example.com.", TTL: time.Hour, Priority: u16(10)},
		{Type: "SRV", Name: "_sip._tcp", Value: "10 5060 sip.example.com.", TTL: time.Minute, Priority: u16(5)},
		{Type: "A", Name: "www", Value: "192.0.2.1"},
		{Type: "TXT", Name: "x", Value: "v", TTL: 500 * time.Millisecond},
	}
	for _, rec := range recs {
		got := fromLibdnsRecord(toLibdnsRecord(rec))
		if !reflect.DeepEqual(got, rec) {
			t.Errorf("round trip of %+v: got %+v", rec, got)
		}
	}
}

// TestRegistryNamespaceTable ensures the dns.providers namespace is
// declared with the dns-provider capability, mirroring Register's switch.
func TestRegistryNamespaceTable(t *testing.T) {
	for _, ns := range supportedNamespaces {
		if ns.prefix == "dns.providers." {
			if ns.cap != runtime.CapDNSProvider {
				t.Fatalf("dns.providers. mapped to capability %q, want %q", ns.cap, runtime.CapDNSProvider)
			}
			return
		}
	}
	t.Fatal("dns.providers. missing from supportedNamespaces")
}
