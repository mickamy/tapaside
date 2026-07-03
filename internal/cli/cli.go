package cli

import (
	"fmt"
	"io"

	"github.com/mickamy/tapaside/internal/exit"
)

type subcommand struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
	usage   func(w io.Writer)
}

var subcommands = []subcommand{
	{
		name:    "proxy",
		summary: "Run the sidecar proxy that relays client sessions to the upstream database",
		run:     runProxy,
		usage:   printProxyUsage,
	},
	{
		name:    "policy",
		summary: "Validate and inspect policy configuration",
		run:     runPolicy,
		usage:   printPolicyUsage,
	},
	{
		name:    "audit",
		summary: "Search and tail the local audit log",
		run:     runAudit,
		usage:   printAuditUsage,
	},
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		PrintUsage(stderr)

		return exit.Usage
	}

	c, ok := lookup(args[0])
	if !ok {
		fmt.Fprintf(stderr, "tapaside: unknown command %q\n", args[0])
		fmt.Fprintln(stderr, "Run 'tapaside --help' for usage.")

		return exit.Usage
	}

	rest := args[1:]
	if wantsHelp(rest) {
		c.usage(stdout)

		return exit.OK
	}

	return c.run(rest, stdout, stderr)
}

func lookup(name string) (subcommand, bool) {
	for _, c := range subcommands {
		if c.name == name {
			return c, true
		}
	}

	return subcommand{}, false
}

func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "--help" || a == "-help" || a == "-h" {
			return true
		}
	}

	return false
}

func PrintUsage(w io.Writer) {
	fmt.Fprintln(w, "tapaside — transparent PostgreSQL sidecar proxy. Policy enforcement and audit are in development.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "USAGE:")
	fmt.Fprintln(w, "  tapaside <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "COMMANDS:")

	width := 0

	for _, c := range subcommands {
		width = max(width, len(c.name))
	}

	for _, c := range subcommands {
		fmt.Fprintf(w, "  %-*s  %s\n", width, c.name, c.summary)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "EXAMPLES:")
	fmt.Fprintln(w, "  # Run a sidecar in front of PostgreSQL")
	fmt.Fprintln(w, "  tapaside proxy --listen 127.0.0.1:5433 --upstream db.internal:5432")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  # Validate a policy file before deploying it")
	fmt.Fprintln(w, "  tapaside policy check policy.yaml")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  # Tail the local audit log")
	fmt.Fprintln(w, "  tapaside audit tail")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "FLAGS:")
	fmt.Fprintln(w, "  --version, -v    Print tapaside version")
	fmt.Fprintln(w, "  --help, -h       Show this help")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'tapaside <command> --help' for command-specific flags.")
	fmt.Fprintln(w, "More: https://github.com/mickamy/tapaside")
}

func notImplemented(_ []string, _, stderr io.Writer) int {
	fmt.Fprintln(stderr, "tapaside: not implemented yet")

	return exit.NotImplemented
}
