package gen

// descriptors_test.go asserts the canonical-ABI sizes and alignments of the
// shared type descriptors against the resolved WIT model (wit-bindgen dump
// of caddy-plugin.wit.json).

import (
	"testing"

	"github.com/elee1766/caddy-wit/pkg/abi"
)

func TestDescriptorLayouts(t *testing.T) {
	cases := []struct {
		name  string
		t     abi.Type
		size  uint32
		align uint32
	}{
		{"plugin-error", pluginErrorT, 12, 4},
		{"key-info", keyInfoT, 32, 8},
		{"event", eventT, 40, 8},
		{"file-info", fileInfoT, 40, 8},
		{"directive-position", directivePositionT, 1, 1},
		{"caddyfile-order", caddyfileOrderT, 12, 4},
		{"module-decl", moduleDeclT, 36, 4},
		{"plugin-info", pluginInfoT, 28, 4},
		{"token", tokenT, 24, 4},
		{"issued-certificate", issuedCertT, 20, 4},
		{"certificate-key-pair", certKeyPairT, 24, 4},
		{"handler-error", handlerErrorT, 12, 4},
		{"level", levelT, 1, 1},
		{"upstream", upstreamT, 12, 4},
	}
	for _, c := range cases {
		if got := c.t.Size(); got != c.size {
			t.Errorf("%s: size = %d, want %d", c.name, got, c.size)
		}
		if got := c.t.Align(); got != c.align {
			t.Errorf("%s: align = %d, want %d", c.name, got, c.align)
		}
	}
}

// TestHostSigRetptr spot-checks the dump's core signatures: result-typed
// host imports take a trailing i32 retptr and return nothing, while
// bool-returning ones return a single i32.
func TestHostSigRetptr(t *testing.T) {
	// host-storage.store: params=[key0 key1 value0 value1 result] results=[]
	params, results := ftHostStorageStore.HostSig()
	if len(params) != 5 || len(results) != 0 {
		t.Errorf("host-storage.store: got %d params / %d results, want 5 / 0", len(params), len(results))
	}
	// host-storage.exists: params=[key0 key1] results=[result0]
	params, results = ftHostStorageExists.HostSig()
	if len(params) != 2 || len(results) != 1 {
		t.Errorf("host-storage.exists: got %d params / %d results, want 2 / 1", len(params), len(results))
	}
	// event-handler.handle (as exported by the guest):
	// params=[inst0 evt0..evt8] results=[retptr]
	params, results = ftEventHandlerHandle.ExportSig()
	if len(params) != 10 || len(results) != 1 {
		t.Errorf("event-handler.handle: got %d params / %d results, want 10 / 1", len(params), len(results))
	}
	// log.log: params=[lvl0 msg0 msg1 fields0 fields1] results=[]
	params, results = ftLogLog.HostSig()
	if len(params) != 5 || len(results) != 0 {
		t.Errorf("log.log: got %d params / %d results, want 5 / 0", len(params), len(results))
	}
	// http-types.next: params=[req0 resp0 result] results=[]
	params, results = ftHTTPNext.HostSig()
	if len(params) != 3 || len(results) != 0 {
		t.Errorf("next: got %d params / %d results, want 3 / 0", len(params), len(results))
	}
}
