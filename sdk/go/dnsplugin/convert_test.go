package dnsplugin

import (
	"reflect"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func u16(v uint16) *uint16 { return &v }

func TestToLibdnsRecordTXT(t *testing.T) {
	rec := ToLibdnsRecord(WireRecord{
		Type:       "TXT",
		Name:       "_acme-challenge.www",
		Value:      "token-value",
		TTLSeconds: 120,
	})
	txt, ok := rec.(libdns.TXT)
	if !ok {
		t.Fatalf("record = %T, want libdns.TXT", rec)
	}
	want := libdns.TXT{Name: "_acme-challenge.www", TTL: 2 * time.Minute, Text: "token-value"}
	if txt != want {
		t.Errorf("TXT = %+v, want %+v", txt, want)
	}
}

func TestToLibdnsRecordMXRejoinsPriority(t *testing.T) {
	rec := ToLibdnsRecord(WireRecord{
		Type:       "MX",
		Name:       "@",
		Value:      "mail.example.com.",
		TTLSeconds: 3600,
		Priority:   u16(10),
	})
	mx, ok := rec.(libdns.MX)
	if !ok {
		t.Fatalf("record = %T, want libdns.MX", rec)
	}
	if mx.Preference != 10 || mx.Target != "mail.example.com." {
		t.Errorf("MX = %+v", mx)
	}
	if got := mx.RR().Data; got != "10 mail.example.com." {
		t.Errorf("RR().Data = %q, want %q", got, "10 mail.example.com.")
	}
}

func TestToLibdnsRecordSRVRejoinsPriority(t *testing.T) {
	rec := ToLibdnsRecord(WireRecord{
		Type:       "SRV",
		Name:       "_sip._tcp",
		Value:      "5 5060 sip.example.com.",
		TTLSeconds: 60,
		Priority:   u16(1),
	})
	srv, ok := rec.(libdns.SRV)
	if !ok {
		t.Fatalf("record = %T, want libdns.SRV", rec)
	}
	if srv.Priority != 1 || srv.Weight != 5 || srv.Port != 5060 || srv.Target != "sip.example.com." {
		t.Errorf("SRV = %+v", srv)
	}
}

func TestToLibdnsRecordUnparsableFallsBackToRR(t *testing.T) {
	rec := ToLibdnsRecord(WireRecord{
		Type:       "A",
		Name:       "bad",
		Value:      "not-an-ip",
		TTLSeconds: 30,
	})
	rr, ok := rec.(libdns.RR)
	if !ok {
		t.Fatalf("record = %T, want libdns.RR fallback", rec)
	}
	want := libdns.RR{Name: "bad", TTL: 30 * time.Second, Type: "A", Data: "not-an-ip"}
	if rr != want {
		t.Errorf("RR = %+v, want %+v", rr, want)
	}
}

func TestToLibdnsRecordPriorityWithEmptyValue(t *testing.T) {
	rec := ToLibdnsRecord(WireRecord{Type: "MX", Name: "@", Priority: u16(20)})
	if got := rec.RR().Data; got != "20" {
		t.Errorf("RR().Data = %q, want %q", got, "20")
	}
}

func TestFromLibdnsRecordSplitsPriority(t *testing.T) {
	got := FromLibdnsRecord(libdns.MX{
		Name:       "@",
		TTL:        time.Hour,
		Preference: 10,
		Target:     "mail.example.com.",
	})
	want := WireRecord{
		Type:       "MX",
		Name:       "@",
		Value:      "mail.example.com.",
		TTLSeconds: 3600,
		Priority:   u16(10),
	}
	if got.Type != want.Type || got.Name != want.Name || got.Value != want.Value ||
		got.TTLSeconds != want.TTLSeconds || got.Priority == nil || *got.Priority != *want.Priority {
		t.Errorf("WireRecord = %+v, want %+v", got, want)
	}
}

func TestFromLibdnsRecordTXTNoSplit(t *testing.T) {
	got := FromLibdnsRecord(libdns.TXT{Name: "txt", TTL: 300 * time.Second, Text: "10 not a priority"})
	if got.Priority != nil {
		t.Errorf("TXT must not split priority; got %+v", got)
	}
	if got.Value != "10 not a priority" {
		t.Errorf("Value = %q", got.Value)
	}
	if got.TTLSeconds != 300 {
		t.Errorf("TTLSeconds = %d, want 300", got.TTLSeconds)
	}
}

func TestRoundTripThroughHostShim(t *testing.T) {
	records := []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", TTL: 60 * time.Second, Text: "tok"},
		libdns.MX{Name: "@", TTL: time.Hour, Preference: 5, Target: "mx.example.com."},
		libdns.SRV{Service: "sip", Transport: "tcp", Name: "@", TTL: 60 * time.Second,
			Priority: 1, Weight: 2, Port: 5060, Target: "sip.example.com."},
	}
	for _, rec := range records {
		back := ToLibdnsRecord(FromLibdnsRecord(rec))
		if !reflect.DeepEqual(rec.RR(), back.RR()) {
			t.Errorf("round trip: got %+v, want %+v", back.RR(), rec.RR())
		}
	}
}

func TestRecordSliceHelpers(t *testing.T) {
	in := []WireRecord{{Type: "TXT", Name: "a", Value: "x", TTLSeconds: 1}}
	libRecs := ToLibdnsRecords(in)
	if len(libRecs) != 1 {
		t.Fatalf("len = %d", len(libRecs))
	}
	out := FromLibdnsRecords(libRecs)
	if len(out) != 1 || out[0].Name != "a" {
		t.Fatalf("out = %+v", out)
	}
}
