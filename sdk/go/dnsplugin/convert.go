// Package dnsplugin provides conversion utilities between libdns records
// and the WIT dns-record representation, plus generic Caddyfile-to-JSON
// mapping for DNS provider plugins.
package dnsplugin

import (
	"strconv"
	"strings"
	"time"

	"go.bytecodealliance.org/cm"

	"github.com/libdns/libdns"

	dnsprovider "github.com/elee1766/caddy-wit/sdk/go/gen/caddy/plugin/dns-provider"
)

// WireRecord is the caddy:plugin/dns-provider dns-record in plain Go form
// (no cm.* types), so the conversion logic compiles and tests on the host.
type WireRecord struct {
	// Type is the RR type, e.g. "TXT", "A", "CNAME".
	Type       string
	Name       string
	Value      string
	TTLSeconds uint32
	Priority   *uint16 // nil when the type has no priority
}

// typeHasLeadingPriority reports whether rtype's RDATA begins with an
// integral priority field.
func typeHasLeadingPriority(rtype string) bool {
	switch rtype {
	case "MX", "SRV", "HTTPS", "SVCB":
		return true
	}
	return false
}

// ToLibdnsRecord converts a WIT dns-record into a libdns record.
func ToLibdnsRecord(r WireRecord) libdns.Record {
	data := r.Value
	if r.Priority != nil {
		if data == "" {
			data = strconv.FormatUint(uint64(*r.Priority), 10)
		} else {
			data = strconv.FormatUint(uint64(*r.Priority), 10) + " " + data
		}
	}
	rr := libdns.RR{
		Name: r.Name,
		TTL:  time.Duration(r.TTLSeconds) * time.Second,
		Type: r.Type,
		Data: data,
	}
	parsed, err := rr.Parse()
	if err != nil {
		return rr
	}
	return parsed
}

// ToLibdnsRecords converts a slice of WireRecords to libdns records.
func ToLibdnsRecords(recs []WireRecord) []libdns.Record {
	out := make([]libdns.Record, len(recs))
	for i, r := range recs {
		out[i] = ToLibdnsRecord(r)
	}
	return out
}

// FromLibdnsRecord converts a libdns record into the WIT dns-record
// representation.
func FromLibdnsRecord(rec libdns.Record) WireRecord {
	rr := rec.RR()
	out := WireRecord{
		Type:       rr.Type,
		Name:       rr.Name,
		Value:      rr.Data,
		TTLSeconds: uint32(rr.TTL / time.Second),
	}
	if typeHasLeadingPriority(rr.Type) && rr.Data != "" {
		first, rest, _ := strings.Cut(rr.Data, " ")
		if prio, err := strconv.ParseUint(first, 10, 16); err == nil {
			p := uint16(prio)
			out.Priority = &p
			out.Value = rest
		}
	}
	return out
}

// FromLibdnsRecords converts a slice of libdns records to WireRecords.
func FromLibdnsRecords(recs []libdns.Record) []WireRecord {
	out := make([]WireRecord, len(recs))
	for i, r := range recs {
		out[i] = FromLibdnsRecord(r)
	}
	return out
}

// FromWireList converts generated binding DNS records into libdns records.
func FromWireList(records cm.List[dnsprovider.DNSRecord]) []libdns.Record {
	in := records.Slice()
	wire := make([]WireRecord, len(in))
	for i, r := range in {
		wire[i] = WireRecord{
			Type:       r.RrType,
			Name:       r.Name,
			Value:      r.Value,
			TTLSeconds: r.TTLSeconds,
			Priority:   r.Priority.Some(),
		}
	}
	return ToLibdnsRecords(wire)
}

// ToWireList converts libdns records into generated binding DNS records.
func ToWireList(recs []libdns.Record) cm.List[dnsprovider.DNSRecord] {
	wire := FromLibdnsRecords(recs)
	out := make([]dnsprovider.DNSRecord, len(wire))
	for i, r := range wire {
		priority := cm.None[uint16]()
		if r.Priority != nil {
			priority = cm.Some(*r.Priority)
		}
		out[i] = dnsprovider.DNSRecord{
			RrType:     r.Type,
			Name:       r.Name,
			Value:      r.Value,
			TTLSeconds: r.TTLSeconds,
			Priority:   priority,
		}
	}
	return cm.ToList(out)
}
