package shim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/elee1766/caddy-wit/pkg/runtime"
)

// EventHandler adapts a wasm plugin module in the events.handlers.*
// namespace to the caddyevents handler module interface.
type EventHandler struct {
	shimCore
}

func newEventHandler(lp *LoadedPlugin, moduleID string) *EventHandler {
	return &EventHandler{shimCore{lp: lp, moduleID: moduleID}}
}

// CaddyModule returns the Caddy module information.
func (e *EventHandler) CaddyModule() caddy.ModuleInfo {
	lp, id := e.lp, e.moduleID
	return caddy.ModuleInfo{
		ID:  caddy.ModuleID(id),
		New: func() caddy.Module { return newEventHandler(lp, id) },
	}
}

// Provision implements caddy.Provisioner. Event handler modules are
// provisioned by the events app itself, so the guest gets no emit-event
// host import: ctx.App("events") here would reference the module's own
// host app mid-provision, which Caddy forbids.
func (e *EventHandler) Provision(ctx caddy.Context) error {
	return e.provisionInstance(ctx, false)
}

// Validate implements caddy.Validator.
func (e *EventHandler) Validate() error { return e.validateInstance() }

// Cleanup implements caddy.CleanerUpper.
func (e *EventHandler) Cleanup() error { return e.cleanupInstance() }

// Handle implements the caddyevents handler interface by forwarding the
// event (with its data serialized as JSON) to the guest.
//
// Interface verified against caddy v2.11.4 (modules/caddyevents/app.go):
//
//	type Handler interface { Handle(context.Context, caddy.Event) error }
//
// caddy.Event accessors: ID() uuid.UUID, Timestamp() time.Time,
// Name() string, Origin() caddy.Module (may be nil), plus the exported
// Data map[string]any field.
func (e *EventHandler) Handle(ctx context.Context, event caddy.Event) error {
	if e.inst == nil {
		return fmt.Errorf("module %s: wasm instance not provisioned", e.moduleID)
	}

	dataJSON := "{}"
	if event.Data != nil {
		b, err := json.Marshal(event.Data)
		if err != nil {
			return fmt.Errorf("module %s: marshaling event data: %w", e.moduleID, err)
		}
		dataJSON = string(b)
	}

	var origin string
	if om := event.Origin(); om != nil {
		origin = string(om.CaddyModule().ID)
	}

	err := e.inst.HandleEvent(ctx, runtime.Event{
		ID:        event.ID().String(),
		Name:      event.Name(),
		Timestamp: event.Timestamp(),
		Origin:    origin,
		DataJSON:  dataJSON,
	})
	// The events app aborts propagation when errors.Is(err,
	// caddy.ErrEventAborted); translate the runtime's sentinel.
	if errors.Is(err, runtime.ErrEventAborted) {
		return caddy.ErrEventAborted
	}
	return err
}

// Interface guards
var (
	_ caddy.Provisioner   = (*EventHandler)(nil)
	_ caddy.Validator     = (*EventHandler)(nil)
	_ caddy.CleanerUpper  = (*EventHandler)(nil)
	_ caddyevents.Handler = (*EventHandler)(nil)
)
