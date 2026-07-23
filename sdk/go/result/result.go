// Package result provides short constructors for the cm.Result types used
// in caddy:plugin WIT exports, hiding the three-type-parameter generics
// from plugin authors.
//
// Instead of:
//
//	type R = cm.Result[string, lifecycle.Instance, string]
//	return cm.OK[R](lifecycle.InstanceResourceNew(1))
//	return cm.Err[R]("bad config")
//
// Write:
//
//	return result.ProvisionOK(lifecycle.InstanceResourceNew(1))
//	return result.ProvisionErr("bad config")
package result

import (
	"go.bytecodealliance.org/cm"

	"github.com/elee1766/caddy-wit/sdk/go/gen/caddy/plugin/config"
	dnsprovider "github.com/elee1766/caddy-wit/sdk/go/gen/caddy/plugin/dns-provider"
	httphandler "github.com/elee1766/caddy-wit/sdk/go/gen/caddy/plugin/http-handler"
	"github.com/elee1766/caddy-wit/sdk/go/gen/caddy/plugin/lifecycle"
)

// --- lifecycle ---

// Provision is the return type of lifecycle.Exports.Instance.Provision.
type Provision = cm.Result[string, lifecycle.Instance, string]

// ProvisionOK returns a successful provision result carrying the instance.
func ProvisionOK(inst lifecycle.Instance) Provision { return cm.OK[Provision](inst) }

// ProvisionErr returns a failed provision result.
func ProvisionErr(msg string) Provision { return cm.Err[Provision](msg) }

// Validate is the return type of lifecycle.Exports.Instance.Validate.
type Validate = cm.Result[string, struct{}, string]

// ValidateOK returns a successful validation.
func ValidateOK() Validate { return cm.OK[Validate](struct{}{}) }

// ValidateErr returns a validation failure.
func ValidateErr(msg string) Validate { return cm.Err[Validate](msg) }

// --- config ---

// Caddyfile is the return type of config.Exports.UnmarshalCaddyfile.
type Caddyfile = cm.Result[string, config.JSON, string]

// CaddyfileOK returns parsed Caddyfile config as JSON.
func CaddyfileOK(json string) Caddyfile { return cm.OK[Caddyfile](config.JSON(json)) }

// CaddyfileErr returns a Caddyfile parsing error.
func CaddyfileErr(msg string) Caddyfile { return cm.Err[Caddyfile](msg) }

// --- dns-provider ---

// DNS is the return type of dns-provider Get/Append/Set/DeleteRecords.
type DNS = cm.Result[cm.List[dnsprovider.DNSRecord], cm.List[dnsprovider.DNSRecord], string]

// DNSOK returns a successful DNS operation result.
func DNSOK(records cm.List[dnsprovider.DNSRecord]) DNS { return cm.OK[DNS](records) }

// DNSErr returns a failed DNS operation result.
func DNSErr(msg string) DNS { return cm.Err[DNS](msg) }

// --- http-handler ---

// Serve is the return type of httphandler.Exports.Serve.
type Serve = cm.Result[httphandler.PluginError, struct{}, httphandler.PluginError]

// ServeOK returns a successful serve result (no error).
func ServeOK() Serve { return cm.OK[Serve](struct{}{}) }

// ServeErr returns a failed serve result. Pass status 0 to omit the HTTP
// status code from the error.
func ServeErr(msg string, status uint16) Serve {
	e := httphandler.PluginError{Message: msg}
	if status != 0 {
		e.Status = cm.Some(status)
	}
	return cm.Err[Serve](e)
}
