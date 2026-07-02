package cli

import (
	"fmt"
	"io"
)

func runProxy(args []string, stdout, stderr io.Writer) int {
	return notImplemented(args, stdout, stderr)
}

func printProxyUsage(w io.Writer) {
	fmt.Fprintln(w, "tapaside proxy — run the sidecar proxy in front of PostgreSQL/MySQL/TiDB.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "USAGE:")
	fmt.Fprintln(w, "  tapaside proxy --upstream <addr> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Listens on loopback for plaintext client connections, connects to the upstream")
	fmt.Fprintln(w, "database over TLS (verify-full), evaluates policy locally before each query,")
	fmt.Fprintln(w, "and writes an audit record for every decision.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "FLAGS:")
	fmt.Fprintln(w, "  --listen <addr>     Address to listen on (default: 127.0.0.1:5433)")
	fmt.Fprintln(w, "  --upstream <addr>   Upstream database address (required)")
	fmt.Fprintln(w, "  --policy <file>     Policy file to enforce")
	fmt.Fprintln(w, "  --audit <file>      Append audit records (JSONL) to this file")
	fmt.Fprintln(w, "  --help, -h          Show this help")
}
