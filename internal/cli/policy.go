package cli

import (
	"fmt"
	"io"
)

func runPolicy(args []string, stdout, stderr io.Writer) int {
	return notImplemented(args, stdout, stderr)
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
