package shim

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
	"github.com/elee1766/caddy-wit/pkg/runtime"
	"github.com/libdns/libdns"
)

// DNSProvider adapts a wasm plugin module in the dns.providers.*
// namespace to the libdns record interfaces, which is what Caddy requires
// of DNS provider modules:
//
//   - certmagic v0.25.3 solves ACME DNS-01 challenges through
//     certmagic.DNSProvider (= libdns.RecordAppender + libdns.RecordDeleter);
//     caddy v2.11.4 caddytls/acmeissuer.go type-asserts the loaded
//     dns.providers module to exactly that.
//   - caddy v2.11.4 caddytls/ech.go publishes ECH configs through
//     caddytls.ECHDNSProvider (= libdns.RecordGetter + libdns.RecordSetter).
//
// This shim implements all four libdns v1.x interfaces (RecordGetter,
// RecordAppender, RecordSetter, RecordDeleter), delegating to the guest's
// caddy:plugin/dns-provider export. A provider guest is pure API glue over
// a registrar's HTTP API, so its manifest entry will typically grant the
// "http" permission.
type DNSProvider struct {
	shimCore
}

func newDNSProvider(lp *LoadedPlugin, moduleID string) *DNSProvider {
	return &DNSProvider{shimCore{lp: lp, moduleID: moduleID}}
}

// CaddyModule returns the Caddy module information.
func (p *DNSProvider) CaddyModule() caddy.ModuleInfo {
	lp, id := p.lp, p.moduleID
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID(id),
		New: func() caddy.Module { return newDNSProvider(lp, id) },
	}
}

// Provision implements caddy.Provisioner.
func (p *DNSProvider) Provision(ctx caddy.Context) error {
	return p.provisionInstance(ctx, true)
}

// Validate implements caddy.Validator.
func (p *DNSProvider) Validate() error { return p.validateInstance() }

// Cleanup implements caddy.CleanerUpper.
func (p *DNSProvider) Cleanup() error { return p.cleanupInstance() }

// GetRecords implements libdns.RecordGetter.
//
// Signature verified against libdns v1.1.1:
//
//	GetRecords(ctx context.Context, zone string) ([]Record, error)
func (p *DNSProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if p.inst == nil {
		return nil, fmt.Errorf("module %s: wasm instance not provisioned", p.moduleID)
	}
	recs, err := p.inst.DNSGetRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	return toLibdnsRecords(recs), nil
}

// AppendRecords implements libdns.RecordAppender.
func (p *DNSProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if p.inst == nil {
		return nil, fmt.Errorf("module %s: wasm instance not provisioned", p.moduleID)
	}
	out, err := p.inst.DNSAppendRecords(ctx, zone, fromLibdnsRecords(recs))
	if err != nil {
		return nil, err
	}
	return toLibdnsRecords(out), nil
}

// SetRecords implements libdns.RecordSetter.
func (p *DNSProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if p.inst == nil {
		return nil, fmt.Errorf("module %s: wasm instance not provisioned", p.moduleID)
	}
	out, err := p.inst.DNSSetRecords(ctx, zone, fromLibdnsRecords(recs))
	if err != nil {
		return nil, err
	}
	return toLibdnsRecords(out), nil
}

// DeleteRecords implements libdns.RecordDeleter.
func (p *DNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if p.inst == nil {
		return nil, fmt.Errorf("module %s: wasm instance not provisioned", p.moduleID)
	}
	out, err := p.inst.DNSDeleteRecords(ctx, zone, fromLibdnsRecords(recs))
	if err != nil {
		return nil, err
	}
	return toLibdnsRecords(out), nil
}

// typeHasLeadingPriority reports whether rtype's RDATA begins with an
// integral priority field. These are exactly the RR types libdns v1.1.1
// models with a Priority/Preference field (MX.Preference, SRV.Priority,
// ServiceBinding.Priority for HTTPS/SVCB); their RR().Data serializations
// all lead with that number.
func typeHasLeadingPriority(rtype string) bool {
	switch rtype {
	case "MX", "SRV", "HTTPS", "SVCB":
		return true
	}
	return false
}

// fromLibdnsRecord converts a libdns record (host side) into the WIT
// dns-record representation. It reduces the record to its zone-file RR
// form via RR(); for priority-bearing types the leading priority field of
// the RDATA is split out into DNSRecord.Priority (the WIT record carries
// priority separately), leaving the remainder in Value.
func fromLibdnsRecord(rec libdns.Record) runtime.DNSRecord {
	rr := rec.RR()
	out := runtime.DNSRecord{
		Type:  rr.Type,
		Name:  rr.Name,
		Value: rr.Data,
		TTL:   rr.TTL,
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

func fromLibdnsRecords(recs []libdns.Record) []runtime.DNSRecord {
	out := make([]runtime.DNSRecord, len(recs))
	for i, r := range recs {
		out[i] = fromLibdnsRecord(r)
	}
	return out
}

// toLibdnsRecord converts a guest dns-record back into a libdns record.
// The optional priority is re-joined onto the RDATA (undoing
// fromLibdnsRecord's split), and the resulting RR is parsed into the
// type-specific libdns struct (libdns.TXT, libdns.MX, ...) as the libdns
// interfaces require. Records the libdns parser rejects (e.g. malformed or
// provider-specific data) degrade to the opaque libdns.RR, which still
// satisfies libdns.Record; certmagic's DNS-01 solver only needs RR().
func toLibdnsRecord(r runtime.DNSRecord) libdns.Record {
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
		TTL:  r.TTL,
		Type: r.Type,
		Data: data,
	}
	parsed, err := rr.Parse()
	if err != nil {
		return rr
	}
	return parsed
}

func toLibdnsRecords(recs []runtime.DNSRecord) []libdns.Record {
	out := make([]libdns.Record, len(recs))
	for i, r := range recs {
		out[i] = toLibdnsRecord(r)
	}
	return out
}

// Interface guards
var (
	_ caddy.Provisioner  = (*DNSProvider)(nil)
	_ caddy.Validator    = (*DNSProvider)(nil)
	_ caddy.CleanerUpper = (*DNSProvider)(nil)

	_ libdns.RecordGetter   = (*DNSProvider)(nil)
	_ libdns.RecordAppender = (*DNSProvider)(nil)
	_ libdns.RecordSetter   = (*DNSProvider)(nil)
	_ libdns.RecordDeleter  = (*DNSProvider)(nil)

	// What Caddy actually requires of dns.providers.* modules:
	_ certmagic.DNSProvider   = (*DNSProvider)(nil) // ACME DNS-01 (caddytls/acmeissuer.go)
	_ caddytls.ECHDNSProvider = (*DNSProvider)(nil) // ECH publishing (caddytls/ech.go)
)
