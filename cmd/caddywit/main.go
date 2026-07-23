// Command caddywit manages caddy-wit plugin manifests: JSON lock files
// that pin wasm plugin sources to sha256 hashes. The Caddy loader
// (github.com/elee1766/caddy-wit/pkg/loader) only loads plugins from such a
// manifest, named by the CADDY_WIT_MANIFEST environment variable.
//
// Usage:
//
//	caddywit manifest init <path>                      create an empty manifest
//	caddywit manifest add <path> <source>              fetch source, pin it, append an entry
//	    [-name NAME] [-permissions http,tcp]
//	caddywit manifest pin <path>                       (re)fetch every source and update sha256/size
//	caddywit manifest verify <path>                    verify every entry; non-zero exit on mismatch
//
// The subcommand implementations live in
// github.com/elee1766/caddy-wit/pkg/manifestcli, shared with the
// `caddy wasm manifest` command group of a caddy-wit-enabled Caddy
// binary (cmd/caddy); this command is only argv parsing and dispatch.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/elee1766/caddy-wit/pkg/manifestcli"
)

const usage = `caddywit manages caddy-wit plugin manifests (JSON lock files that pin
wasm plugin sources to sha256 hashes).

Usage:

  caddywit manifest init <path>
        Write an empty version-1 manifest at <path>. Refuses to overwrite.

  caddywit manifest add <path> <source> [-name NAME] [-permissions http,tcp]
        Fetch <source> (a filesystem path, an http(s) URL, or an
        oci://registry/repo[:tag|@sha256:...] wasm OCI artifact; relative
        paths resolve against the manifest's directory), compute its
        sha256 and size, and append an entry. OCI sources are stored in
        digest-pinned form (oci://...@sha256:<manifest digest>) with the
        resolved tag recorded in the entry's "tag" field and the wasm
        layer digest/size in sha256/size. NAME defaults to the source
        basename without the .wasm extension.

        -permissions is a comma-separated list of host capabilities to
        grant the plugin: "http" (outbound HTTP client) and/or "tcp"
        (raw TCP connections). By default a plugin gets no network
        access; permissions are an explicit grant recorded in the
        manifest alongside the hash pin.

  caddywit manifest pin <path>
        (Re)fetch every entry's source and fill/update its sha256 and
        size. OCI entries with a tag are re-resolved to the tag's current
        (possibly new) manifest digest and their source rewritten;
        digest-only OCI entries are checked for reachability and their
        sha256/size refreshed. This is the "update the lockfile"
        operation.

  caddywit manifest verify <path>
        Fetch/read every entry's source and verify its sha256 and size.
        OCI entries are fully verified: pinned manifest digest, wasm
        artifact media types, layer digest, and the optional sha256/size
        layer pins. Prints a per-entry report; exits non-zero on any
        mismatch.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches the CLI; it is the testable entry point.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "manifest":
		return runManifest(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "caddywit: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func runManifest(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch cmd := args[0]; cmd {
	case "init":
		err = cmdInit(args[1:], stdout)
	case "add":
		err = cmdAdd(args[1:], stdout)
	case "pin":
		err = cmdPin(args[1:], stdout)
	case "verify":
		err = cmdVerify(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "caddywit: unknown manifest subcommand %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "caddywit: %v\n", err)
		return 1
	}
	return 0
}

// cmdInit writes an empty v1 manifest, refusing to overwrite.
func cmdInit(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: caddywit manifest init <path>")
	}
	return manifestcli.Init(stdout, args[0])
}

// cmdAdd fetches a source, hashes it, and appends a pinned entry.
func cmdAdd(args []string, stdout io.Writer) error {
	const addUsage = "usage: caddywit manifest add <path> <source> [-name NAME] [-permissions http,tcp]"
	fs := flag.NewFlagSet("manifest add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	name := fs.String("name", "", "entry name (default: source basename without .wasm)")
	permsFlag := fs.String("permissions", "", `comma-separated permissions to grant ("http", "tcp")`)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return fmt.Errorf("%s: %w", addUsage, err)
	}
	if len(pos) != 2 {
		return errors.New(addUsage)
	}
	return manifestcli.Add(stdout, pos[0], pos[1], *name, *permsFlag)
}

// cmdPin refetches every source and updates sha256/size.
func cmdPin(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: caddywit manifest pin <path>")
	}
	return manifestcli.Pin(stdout, args[0])
}

// cmdVerify fetches every source and checks the pinned sha256 and size,
// printing a per-entry report: successes to stdout, failures to stderr.
func cmdVerify(args []string, stdout, stderr io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: caddywit manifest verify <path>")
	}
	return manifestcli.VerifyStreams(stdout, stderr, args[0])
}

// parseArgs parses flags with fs while allowing them to appear either
// before or after positional arguments (the flag package alone stops at
// the first positional). Returns the positional arguments.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for len(args) > 0 {
		switch {
		case args[0] == "--":
			// Explicit terminator: everything after is positional.
			return append(pos, args[1:]...), nil
		case args[0] == "-" || !strings.HasPrefix(args[0], "-"):
			pos = append(pos, args[0])
			args = args[1:]
		default:
			if err := fs.Parse(args); err != nil {
				return nil, err
			}
			args = fs.Args()
		}
	}
	return pos, nil
}
