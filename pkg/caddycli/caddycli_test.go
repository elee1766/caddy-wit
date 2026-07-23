package caddycli

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/cobra"

	"github.com/elee1766/caddy-wit/pkg/loader/manifest"
)

// execWasm builds the `wasm` command tree on a fresh cobra command
// (exactly what Caddy does with the registered CobraFunc) and executes
// it with args, returning the error and captured stdout/stderr.
func execWasm(t *testing.T, args ...string) (error, string, string) {
	t.Helper()
	root := &cobra.Command{Use: "wasm", SilenceUsage: true}
	attachWasmSubcommands(root)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err := root.Execute()
	return err, out.String(), errOut.String()
}

func TestRegisteredWithCaddy(t *testing.T) {
	cmd, ok := caddycmd.Commands()["wasm"]
	if !ok {
		t.Fatal("`wasm` command not registered with caddycmd")
	}
	if cmd.Short == "" || cmd.CobraFunc == nil {
		t.Fatalf("registered command incomplete: %+v", cmd)
	}
}

func TestManifestInitAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")

	err, out, errOut := execWasm(t, "manifest", "init", path)
	if err != nil {
		t.Fatalf("manifest init: %v (stderr %q)", err, errOut)
	}
	if !strings.Contains(out, "wrote empty manifest "+path) {
		t.Fatalf("init output: %q", out)
	}
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	want := "{\n  \"version\": 1,\n  \"plugins\": []\n}\n"
	if string(data) != want {
		t.Fatalf("init wrote %q, want %q", data, want)
	}

	// Re-init must fail through cobra with a non-nil error (Caddy's
	// Main exits non-zero on RunE errors).
	err, _, _ = execWasm(t, "manifest", "init", path)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("re-init: %v", err)
	}

	// Verify the empty manifest: succeeds silently.
	err, out, errOut = execWasm(t, "manifest", "verify", path)
	if err != nil {
		t.Fatalf("manifest verify: %v (stderr %q)", err, errOut)
	}
	if out != "" {
		t.Fatalf("verify of empty manifest should print nothing, got %q", out)
	}

	// Verify a missing manifest: non-nil error.
	err, _, _ = execWasm(t, "manifest", "verify", filepath.Join(dir, "nope.json"))
	if err == nil {
		t.Fatal("verify of missing manifest should fail")
	}
}

func TestManifestAddFlagsAndVerifyFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caddy-wit.json")
	wasmPath := filepath.Join(dir, "local.wasm")
	local := []byte("local plugin bytes")
	if err := os.WriteFile(wasmPath, local, 0o644); err != nil {
		t.Fatal(err)
	}

	if err, _, _ := execWasm(t, "manifest", "init", path); err != nil {
		t.Fatal(err)
	}
	err, out, _ := execWasm(t, "manifest", "add", path, "local.wasm", "--name", "dev", "--permissions", "http,tcp")
	if err != nil {
		t.Fatalf("manifest add: %v", err)
	}
	if !strings.Contains(out, `added "dev"`) || !strings.Contains(out, "permissions: http,tcp") {
		t.Fatalf("add output: %q", out)
	}
	m, lerr := manifest.LoadEditable(path)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(m.Plugins) != 1 || m.Plugins[0].Name != "dev" ||
		m.Plugins[0].SHA256 != manifest.HashBytes(local) ||
		!reflect.DeepEqual(m.Plugins[0].Permissions, []string{"http", "tcp"}) {
		t.Fatalf("plugins = %+v", m.Plugins)
	}

	// Intact entry verifies; ok line goes to stdout.
	err, out, _ = execWasm(t, "manifest", "verify", path)
	if err != nil || !strings.Contains(out, "ok   dev") {
		t.Fatalf("verify: err %v, out %q", err, out)
	}

	// Tamper with the plugin bytes: verify must return an error (so the
	// caddy process exits non-zero) and report the failure on stderr.
	if err := os.WriteFile(wasmPath, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	err, _, errOut := execWasm(t, "manifest", "verify", path)
	if err == nil || !strings.Contains(err.Error(), "manifest verification failed for "+path) {
		t.Fatalf("verify after tamper: %v", err)
	}
	if !strings.Contains(errOut, "FAIL dev") {
		t.Fatalf("verify stderr: %q", errOut)
	}

	// Wrong arity is rejected by cobra.
	if err, _, _ := execWasm(t, "manifest", "add", path); err == nil {
		t.Fatal("add with missing source should fail")
	}
}
