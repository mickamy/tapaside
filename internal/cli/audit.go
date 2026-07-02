package cli

import (
	"fmt"
	"io"
)

func runAudit(args []string, stdout, stderr io.Writer) int {
	return notImplemented(args, stdout, stderr)
}

func printAuditUsage(w io.Writer) {
	fmt.Fprintln(w, "tapaside audit — search and tail the local audit log.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "USAGE:")
	fmt.Fprintln(w, "  tapaside audit tail [--file <path>]")
	fmt.Fprintln(w, "  tapaside audit search [--file <path>] [query]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Reads the JSONL audit log written by the proxy and filters records by")
	fmt.Fprintln(w, "principal, table, or decision.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "FLAGS:")
	fmt.Fprintln(w, "  --file <path>    Audit log to read")
	fmt.Fprintln(w, "  --help, -h       Show this help")
}
