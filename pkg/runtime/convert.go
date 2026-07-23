package runtime

// convert.go holds pure conversions between the public runtime types
// (api.go) and the generated wire types in gen. Time fields cross the
// boundary as milliseconds since the Unix epoch (WIT epoch-ms).

import (
	"time"

	"github.com/elee1766/caddy-wit/pkg/runtime/gen"
)

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func pluginInfoFromGen(gi gen.PluginInfo) PluginInfo {
	info := PluginInfo{
		Name:    gi.Name,
		Version: derefString(gi.Version),
		Modules: make([]ModuleDecl, 0, len(gi.Modules)),
	}
	for _, md := range gi.Modules {
		info.Modules = append(info.Modules, ModuleDecl{
			ID:             md.ID,
			Docs:           derefString(md.Docs),
			CaddyfileOrder: directiveOrderFromGen(md.CaddyfileOrder),
		})
	}
	return info
}

// directivePositionStrings maps gen.DirectivePosition to the strings used
// by httpcaddyfile.Positional ("before"/"after").
var directivePositionStrings = map[gen.DirectivePosition]string{
	gen.DirectiveBefore: "before",
	gen.DirectiveAfter:  "after",
}

func directiveOrderFromGen(co *gen.CaddyfileOrder) *DirectiveOrder {
	if co == nil {
		return nil
	}
	return &DirectiveOrder{
		Position:   directivePositionStrings[co.Position],
		RelativeTo: co.RelativeTo,
	}
}

// directiveOrderToGen is the inverse of directiveOrderFromGen; unknown
// position strings map to nil (treated as "no declared order").
func directiveOrderToGen(do *DirectiveOrder) *gen.CaddyfileOrder {
	if do == nil {
		return nil
	}
	for pos, s := range directivePositionStrings {
		if s == do.Position {
			return &gen.CaddyfileOrder{Position: pos, RelativeTo: do.RelativeTo}
		}
	}
	return nil
}

func tokensToGen(tokens []Token) []gen.Token {
	out := make([]gen.Token, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, gen.Token{
			File:   t.File,
			Line:   t.Line,
			Text:   t.Text,
			Quoted: t.Quoted,
		})
	}
	return out
}

func fileInfoFromGen(fi gen.FileInfo) FileInfo {
	return FileInfo{
		Name:    fi.Name,
		Size:    fi.Size,
		Mode:    fi.Mode,
		ModTime: time.UnixMilli(fi.ModTime),
		Dir:     fi.Dir,
	}
}

func fileInfosFromGen(fis []gen.FileInfo) []FileInfo {
	out := make([]FileInfo, 0, len(fis))
	for _, fi := range fis {
		out = append(out, fileInfoFromGen(fi))
	}
	return out
}

func keyInfoFromGen(ki gen.KeyInfo) KeyInfo {
	return KeyInfo{
		Key:      ki.Key,
		Modified: time.UnixMilli(ki.Modified),
		Size:     ki.Size,
		Terminal: ki.Terminal,
	}
}

func issuedCertificateFromGen(ic gen.IssuedCertificate) IssuedCertificate {
	return IssuedCertificate{
		CertificatePEM: ic.CertificatePEM,
		MetadataJSON:   derefString(ic.Metadata),
	}
}

func certificateKeyPairsFromGen(pairs []gen.CertificateKeyPair) []CertificateKeyPair {
	out := make([]CertificateKeyPair, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, CertificateKeyPair{
			CertificatePEM: p.CertificatePEM,
			KeyPEM:         p.KeyPEM,
			Tags:           p.Tags,
		})
	}
	return out
}

// dnsRecordToGen converts a public DNSRecord to the wire type. TTL is
// truncated to whole seconds (WIT ttl-seconds: u32).
func dnsRecordToGen(r DNSRecord) gen.DNSRecord {
	return gen.DNSRecord{
		RRType:     r.Type,
		Name:       r.Name,
		Value:      r.Value,
		TTLSeconds: uint32(r.TTL / time.Second),
		Priority:   r.Priority,
	}
}

func dnsRecordFromGen(r gen.DNSRecord) DNSRecord {
	return DNSRecord{
		Type:     r.RRType,
		Name:     r.Name,
		Value:    r.Value,
		TTL:      time.Duration(r.TTLSeconds) * time.Second,
		Priority: r.Priority,
	}
}

func dnsRecordsToGen(recs []DNSRecord) []gen.DNSRecord {
	out := make([]gen.DNSRecord, 0, len(recs))
	for _, r := range recs {
		out = append(out, dnsRecordToGen(r))
	}
	return out
}

func dnsRecordsFromGen(recs []gen.DNSRecord) []DNSRecord {
	out := make([]DNSRecord, 0, len(recs))
	for _, r := range recs {
		out = append(out, dnsRecordFromGen(r))
	}
	return out
}

func upstreamsFromGen(gus []gen.Upstream) []Upstream {
	out := make([]Upstream, 0, len(gus))
	for _, g := range gus {
		out = append(out, Upstream{
			Dial:        g.Dial,
			MaxRequests: int(g.MaxRequests),
		})
	}
	return out
}

func eventToGen(ev Event) gen.Event {
	return gen.Event{
		ID:        ev.ID,
		Name:      ev.Name,
		Timestamp: ev.Timestamp.UnixMilli(),
		Origin:    ev.Origin,
		Data:      ev.DataJSON,
	}
}

// pluginErrorFromGen converts a guest-returned plugin-error to the public
// *PluginError (which satisfies error).
func pluginErrorFromGen(pe *gen.PluginError) *PluginError {
	if pe == nil {
		return nil
	}
	out := &PluginError{Message: pe.Message}
	if pe.Status != nil {
		out.Status = int(*pe.Status)
	}
	return out
}

// pluginErrorToGen converts a host-side *PluginError (e.g. from the rest of
// the middleware chain) into the wire representation for the guest.
func pluginErrorToGen(pe *PluginError) *gen.PluginError {
	if pe == nil {
		return nil
	}
	out := &gen.PluginError{Message: pe.Message}
	if pe.Status > 0 && pe.Status <= 0xFFFF {
		s := uint16(pe.Status)
		out.Status = &s
	}
	return out
}
