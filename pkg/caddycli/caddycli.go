// Package caddycli extends Caddy's command line with a `caddy wasm`
// command group for managing caddy-wit WebAssembly plugins. Importing
// this package (for side effects) in a custom Caddy binary registers
// the commands with Caddy's CLI before caddycmd.Main() builds the root
// command:
//
//	import _ "github.com/elee1766/caddy-wit/pkg/caddycli"
//
// The subcommands delegate to github.com/elee1766/caddy-wit/pkg/manifestcli,
// the same implementation behind the standalone caddywit tool, so
// `caddy wasm manifest ...` and `caddywit manifest ...` behave
// identically.
package caddycli

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/cobra"

	"github.com/elee1766/caddy-wit/pkg/manifestcli"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "wasm",
		Usage: "<subcommand>",
		Short: "Manage caddy-wit WebAssembly plugins",
		Long: `
caddy-wit (github.com/elee1766/caddy-wit) loads WebAssembly (WIT
component) plugins into Caddy at startup, exposing Caddy's module
system to wasm guests: HTTP handlers and matchers, and more.

Plugins are declared in a manifest: a JSON lock file (conventionally
caddy-wit.json) that pins every plugin source (filesystem path, http(s)
URL, or oci:// registry artifact) to a sha256 hash. At startup the
loader reads the manifest named by the CADDY_WIT_MANIFEST environment
variable and only loads plugins whose bytes match their pinned hash
(and size, when pinned):

  CADDY_WIT_MANIFEST=/etc/caddy/caddy-wit.json caddy run

The typical workflow:

  caddy wasm manifest init caddy-wit.json
  caddy wasm manifest add caddy-wit.json oci://registry.example.com/plugins/hello:v1
  caddy wasm manifest verify caddy-wit.json
  CADDY_WIT_MANIFEST=caddy-wit.json caddy run

Use 'manifest pin' to update the lock file when upstream sources (for
example a moved OCI tag) change.
`,
		CobraFunc: attachWasmSubcommands,
	})
}

// attachWasmSubcommands populates the `caddy wasm` cobra command with
// its subcommand tree. It is the Command's CobraFunc, split out so
// tests can build the tree on a fresh *cobra.Command without a full
// Caddy binary.
func attachWasmSubcommands(cmd *cobra.Command) {
	cmd.AddCommand(manifestCommand())
}

// manifestCommand builds the `caddy wasm manifest` command group.
func manifestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Manage plugin manifests (JSON lock files pinning wasm sources to sha256 hashes)",
	}

	initCmd := &cobra.Command{
		Use:   "init <path>",
		Short: "Create an empty manifest",
		Long: `
Write an empty version-1 manifest at <path>. Refuses to overwrite an
existing file.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return manifestcli.Init(cmd.OutOrStdout(), args[0])
		},
	}

	addCmd := &cobra.Command{
		Use:   "add <path> <source> [--name <name>] [--permissions http,tcp]",
		Short: "Fetch a source, pin it, and append a manifest entry",
		Long: `
Fetch <source> (a filesystem path, an http(s) URL, or an
oci://registry/repo[:tag|@sha256:...] wasm OCI artifact; relative paths
resolve against the manifest's directory), compute its sha256 and size,
and append an entry to the manifest at <path>. OCI sources are stored
in digest-pinned form (oci://...@sha256:<manifest digest>) with the
resolved tag recorded in the entry's "tag" field and the wasm layer
digest/size in sha256/size.

--name defaults to the source basename without the .wasm extension.

--permissions is a comma-separated list of host capabilities to grant
the plugin: "http" (outbound HTTP client) and/or "tcp" (raw TCP
connections). By default a plugin gets no network access; permissions
are an explicit grant recorded in the manifest alongside the hash pin.
`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := cmd.Flags().GetString("name")
			if err != nil {
				return err
			}
			permissions, err := cmd.Flags().GetString("permissions")
			if err != nil {
				return err
			}
			return manifestcli.Add(cmd.OutOrStdout(), args[0], args[1], name, permissions)
		},
	}
	addCmd.Flags().String("name", "", "entry name (default: source basename without .wasm)")
	addCmd.Flags().String("permissions", "", `comma-separated permissions to grant ("http", "tcp")`)

	pinCmd := &cobra.Command{
		Use:   "pin <path>",
		Short: "(Re)fetch every source and update its sha256/size pins",
		Long: `
(Re)fetch every entry's source in the manifest at <path> and
fill/update its sha256 and size. OCI entries with a tag are re-resolved
to the tag's current (possibly new) manifest digest and their source
rewritten; digest-only OCI entries are checked for reachability and
their sha256/size refreshed. This is the "update the lockfile"
operation. If any source fails to fetch, nothing is written.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return manifestcli.Pin(cmd.OutOrStdout(), args[0])
		},
	}

	verifyCmd := &cobra.Command{
		Use:   "verify <path>",
		Short: "Verify every manifest entry against its pins",
		Long: `
Fetch/read every entry's source in the manifest at <path> and verify
its sha256 and size. OCI entries are fully verified: pinned manifest
digest, wasm artifact media types, layer digest, and the optional
sha256/size layer pins. Prints a per-entry report; exits non-zero on
any mismatch.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return manifestcli.VerifyStreams(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0])
		},
	}

	cmd.AddCommand(initCmd, addCmd, pinCmd, verifyCmd)
	return cmd
}
