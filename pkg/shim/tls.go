package shim

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
)

// TLSIssuer adapts a wasm plugin module in the tls.issuance.* namespace to
// certmagic.Issuer.
type TLSIssuer struct {
	shimCore

	// issuerKey caches the guest's issuer-key at Provision time:
	// certmagic.Issuer.IssuerKey() has no error return and is called
	// frequently (storage paths, cert selection), so we avoid a wasm call
	// per invocation and guarantee a stable value post-provision.
	issuerKey string
}

func newTLSIssuer(lp *LoadedPlugin, moduleID string) *TLSIssuer {
	return &TLSIssuer{shimCore: shimCore{lp: lp, moduleID: moduleID}}
}

// CaddyModule returns the Caddy module information.
func (t *TLSIssuer) CaddyModule() caddy.ModuleInfo {
	lp, id := t.lp, t.moduleID
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID(id),
		New: func() caddy.Module { return newTLSIssuer(lp, id) },
	}
}

// Provision implements caddy.Provisioner. It also eagerly fetches and
// caches the guest's issuer key.
func (t *TLSIssuer) Provision(ctx caddy.Context) error {
	if err := t.provisionInstance(ctx, true); err != nil {
		return err
	}
	kctx, cancel := bootCtx()
	defer cancel()
	key, err := t.inst.IssuerKey(kctx)
	if err != nil {
		_ = t.cleanupInstance()
		return fmt.Errorf("module %s: getting issuer key: %w", t.moduleID, err)
	}
	t.issuerKey = key
	return nil
}

// Validate implements caddy.Validator.
func (t *TLSIssuer) Validate() error { return t.validateInstance() }

// Cleanup implements caddy.CleanerUpper.
func (t *TLSIssuer) Cleanup() error { return t.cleanupInstance() }

// IssuerKey implements certmagic.Issuer. It returns the value cached at
// Provision time (empty before provisioning).
func (t *TLSIssuer) IssuerKey() string { return t.issuerKey }

// Issue implements certmagic.Issuer by passing the CSR's raw DER encoding
// to the guest's tls-issuer.issue export.
//
// Signature verified against certmagic v0.25.3:
//
//	Issue(ctx context.Context, request *x509.CertificateRequest) (*IssuedCertificate, error)
func (t *TLSIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	if t.inst == nil {
		return nil, fmt.Errorf("module %s: wasm instance not provisioned", t.moduleID)
	}
	ic, err := t.inst.Issue(ctx, csr.Raw)
	if err != nil {
		return nil, err
	}
	out := &certmagic.IssuedCertificate{Certificate: ic.CertificatePEM}
	if ic.MetadataJSON != "" {
		// certmagic requires Metadata to be JSON-serializable; keep the
		// guest's JSON verbatim.
		out.Metadata = json.RawMessage(ic.MetadataJSON)
	}
	return out, nil
}

// TLSCertLoader adapts a wasm plugin module in the tls.certificates.*
// namespace to caddytls.CertificateLoader.
type TLSCertLoader struct {
	shimCore
}

func newTLSCertLoader(lp *LoadedPlugin, moduleID string) *TLSCertLoader {
	return &TLSCertLoader{shimCore{lp: lp, moduleID: moduleID}}
}

// CaddyModule returns the Caddy module information.
func (t *TLSCertLoader) CaddyModule() caddy.ModuleInfo {
	lp, id := t.lp, t.moduleID
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID(id),
		New: func() caddy.Module { return newTLSCertLoader(lp, id) },
	}
}

// Provision implements caddy.Provisioner.
func (t *TLSCertLoader) Provision(ctx caddy.Context) error {
	return t.provisionInstance(ctx, true)
}

// Validate implements caddy.Validator.
func (t *TLSCertLoader) Validate() error { return t.validateInstance() }

// Cleanup implements caddy.CleanerUpper.
func (t *TLSCertLoader) Cleanup() error { return t.cleanupInstance() }

// LoadCertificates implements caddytls.CertificateLoader by parsing the
// guest's PEM pairs and attaching its tags.
//
// Interface verified against caddy v2.11.4:
//
//	type CertificateLoader interface { LoadCertificates() ([]Certificate, error) }
//	type Certificate struct { tls.Certificate; Tags []string }
func (t *TLSCertLoader) LoadCertificates() ([]caddytls.Certificate, error) {
	if t.inst == nil {
		return nil, fmt.Errorf("module %s: wasm instance not provisioned", t.moduleID)
	}
	ctx, cancel := bootCtx()
	defer cancel()
	pairs, err := t.inst.LoadCertificates(ctx)
	if err != nil {
		return nil, fmt.Errorf("module %s: loading certificates from guest: %w", t.moduleID, err)
	}
	certs := make([]caddytls.Certificate, 0, len(pairs))
	for i, kp := range pairs {
		cert, err := tls.X509KeyPair(kp.CertificatePEM, kp.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("module %s: certificate %d: parsing key pair: %w", t.moduleID, i, err)
		}
		certs = append(certs, caddytls.Certificate{Certificate: cert, Tags: kp.Tags})
	}
	return certs, nil
}

// Interface guards
var (
	_ caddy.Provisioner          = (*TLSIssuer)(nil)
	_ caddy.Validator            = (*TLSIssuer)(nil)
	_ caddy.CleanerUpper         = (*TLSIssuer)(nil)
	_ certmagic.Issuer           = (*TLSIssuer)(nil)
	_ caddy.Provisioner          = (*TLSCertLoader)(nil)
	_ caddy.Validator            = (*TLSCertLoader)(nil)
	_ caddy.CleanerUpper         = (*TLSCertLoader)(nil)
	_ caddytls.CertificateLoader = (*TLSCertLoader)(nil)
)
