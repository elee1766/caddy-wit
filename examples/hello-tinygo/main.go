// Reference caddy-wit plugin in Go, compiled with TinyGo (-target=wasip1)
// against wit-bindgen-go generated bindings.
//
// Registers `http.handlers.wit_hello_go`. Config: {"message": "..."}.
// Caddyfile:  wit_hello_go <message>
//
//go:generate go tool wit-bindgen-go generate --world http-handler-plugin --out gen ../../wit
package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"unsafe"

	"go.bytecodealliance.org/cm"

	"github.com/elee1766/caddy-wit/examples/hello-tinygo/gen/caddy/plugin/config"
	httphandler "github.com/elee1766/caddy-wit/examples/hello-tinygo/gen/caddy/plugin/http-handler"
	httptypes "github.com/elee1766/caddy-wit/examples/hello-tinygo/gen/caddy/plugin/http-types"
	"github.com/elee1766/caddy-wit/examples/hello-tinygo/gen/caddy/plugin/lifecycle"
	"github.com/elee1766/caddy-wit/examples/hello-tinygo/gen/caddy/plugin/log"
	"github.com/elee1766/caddy-wit/examples/hello-tinygo/gen/caddy/plugin/manifest"
)

const moduleID = "http.handlers.wit_hello_go"

type helloInstance struct {
	message string
}

// Guest-side resource table: rep -> instance state.
var (
	instances        = map[cm.Rep]*helloInstance{}
	nextRep   cm.Rep = 1
)

type helloConfig struct {
	Message string `json:"message"`
}

func init() {
	manifest.Exports.Describe = func() manifest.PluginInfo {
		docs := "Hello-world middleware demonstrating caddy-wit from TinyGo"
		return manifest.PluginInfo{
			Name:    "hello-tinygo",
			Version: cm.Some("0.1.0"),
			Modules: cm.ToList([]manifest.ModuleDecl{{
				ID:   moduleID,
				Docs: cm.Some(docs),
				// Order the directive before `respond` so it runs even
				// when a terminal standard directive follows it.
				CaddyfileOrder: cm.Some(manifest.CaddyfileOrder{
					Position:   manifest.DirectivePositionBefore,
					RelativeTo: "respond",
				}),
			}}),
		}
	}

	lifecycle.Exports.Instance.Provision = func(id string, cfg lifecycle.JSON) cm.Result[string, lifecycle.Instance, string] {
		if id != moduleID {
			return cm.Err[cm.Result[string, lifecycle.Instance, string]](fmt.Sprintf("unknown module id: %s", id))
		}
		var parsed helloConfig
		if strings.TrimSpace(string(cfg)) != "" {
			if err := json.Unmarshal([]byte(cfg), &parsed); err != nil {
				return cm.Err[cm.Result[string, lifecycle.Instance, string]]("invalid config: " + err.Error())
			}
		}
		if parsed.Message == "" {
			parsed.Message = "hello from tinygo wasm"
		}
		rep := nextRep
		nextRep++
		instances[rep] = &helloInstance{message: parsed.Message}
		log.Log(log.LevelInfo, "wit_hello_go provisioned",
			cm.ToList([][2]string{{"message", parsed.Message}}))
		return cm.OK[cm.Result[string, lifecycle.Instance, string]](lifecycle.InstanceResourceNew(rep))
	}

	lifecycle.Exports.Instance.Validate = func(self cm.Rep) cm.Result[string, struct{}, string] {
		inst := instances[self]
		if inst == nil || inst.message == "" {
			return cm.Err[cm.Result[string, struct{}, string]]("message must not be empty")
		}
		return cm.OK[cm.Result[string, struct{}, string]](struct{}{})
	}

	lifecycle.Exports.Instance.Cleanup = func(self cm.Rep) {
		log.Log(log.LevelDebug, "wit_hello_go cleaned up", cm.ToList([][2]string{}))
	}

	lifecycle.Exports.Instance.Destructor = func(self cm.Rep) {
		delete(instances, self)
	}

	config.Exports.UnmarshalCaddyfile = func(id string, tokens cm.List[config.Token]) cm.Result[string, config.JSON, string] {
		if id != moduleID {
			return cm.Err[cm.Result[string, config.JSON, string]](fmt.Sprintf("unknown module id: %s", id))
		}
		var args []string
		for i, tok := range tokens.Slice() {
			if i == 0 {
				continue // directive name
			}
			args = append(args, tok.Text)
		}
		out, err := json.Marshal(helloConfig{Message: strings.Join(args, " ")})
		if err != nil {
			return cm.Err[cm.Result[string, config.JSON, string]](err.Error())
		}
		return cm.OK[cm.Result[string, config.JSON, string]](config.JSON(out))
	}

	httphandler.Exports.Serve = func(inst, reqRep, respRep cm.Rep) cm.Result[httphandler.PluginError, struct{}, httphandler.PluginError] {
		type serveResult = cm.Result[httphandler.PluginError, struct{}, httphandler.PluginError]
		st := instances[inst]
		if st == nil {
			return cm.Err[serveResult](httphandler.PluginError{Message: "unknown instance"})
		}
		req := httptypes.Request(reqRep)
		resp := httptypes.ResponseWriter(respRep)

		resp.SetHeader("X-Wit-Hello-Go", "1")

		if req.Path() == "/hello" {
			resp.SetHeader("Content-Type", "text/plain; charset=utf-8")
			resp.WriteStatus(200)
			if r := resp.Write(cm.ToList([]byte(st.message))); r.IsErr() {
				return cm.Err[serveResult](httphandler.PluginError{Message: *r.Err()})
			}
			return cm.OK[serveResult](struct{}{})
		}

		req.SetHeader("X-Wit-Saw-Go", req.Method())
		return httptypes.Next(req, resp)
	}
}

// pinned keeps canonical-ABI allocations reachable so TinyGo's GC never
// frees memory the host still references. This reference plugin pins for
// the module's lifetime, which leaks a few bytes per host->guest call
// carrying strings/lists; a production SDK would use an arena reset between
// calls.
var pinned [][]byte

// cabiRealloc implements the Canonical ABI allocator. The host calls it to
// place strings/lists into guest linear memory before invoking exports.
//
//go:wasmexport cabi_realloc
func cabiRealloc(ptr, oldSize, align, newSize uint32) uint32 {
	if align == 0 {
		align = 1
	}
	if newSize == 0 {
		return align // any non-zero aligned pointer is acceptable
	}
	buf := make([]byte, newSize+align)
	pinned = append(pinned, buf)
	addr := uint32(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	aligned := (addr + align - 1) &^ (align - 1)
	if ptr != 0 && oldSize > 0 {
		old := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), oldSize)
		copy(unsafe.Slice((*byte)(unsafe.Pointer(uintptr(aligned))), newSize), old)
	}
	return aligned
}

// main is required for the wasip1 target.
func main() {}
