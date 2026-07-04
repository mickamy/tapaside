package cli

import (
	"fmt"
	"io"

	"github.com/mickamy/tapaside/internal/exit"
	"github.com/mickamy/tapaside/internal/policy"
)

func runPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printPolicyUsage(stderr)

		return exit.Usage
	}

	switch args[0] {
	case "check":
		return runPolicyCheck(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "tapaside: unknown policy command %q\n", args[0])
		fmt.Fprintln(stderr, "Run 'tapaside policy --help' for usage.")

		return exit.Usage
	}
}

func runPolicyCheck(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "tapaside: policy check takes exactly one file")
		fmt.Fprintln(stderr, "Run 'tapaside policy --help' for usage.")

		return exit.Usage
	}

	p, err := policy.Load(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "tapaside: %v\n", err)

		return exit.Error
	}

	if !p.Enforces() {
		fmt.Fprintf(stderr, "tapaside: warning: %s enables no rules; all queries would be allowed\n", args[0])
	}

	fmt.Fprintf(stdout, "%s: ok\n", args[0])

	return exit.OK
}

func printPolicyUsage(w io.Writer) {
	fmt.Fprintln(w, "tapaside policy — validate and inspect policy configuration.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "USAGE:")
	fmt.Fprintln(w, "  tapaside policy check <file>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Parses the policy file and reports errors before you deploy it to a sidecar.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "FLAGS:")
	fmt.Fprintln(w, "  --help, -h       Show this help")
}
