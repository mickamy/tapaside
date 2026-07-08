package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mickamy/tapaside/internal/exit"
	"github.com/mickamy/tapaside/internal/policy"
	"github.com/mickamy/tapaside/internal/proxy"
	"github.com/mickamy/tapaside/internal/proxy/pg"
)

func runProxy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printProxyUsage(stderr) }

	listen := fs.String("listen", "127.0.0.1:5433", "address to listen on")
	upstream := fs.String("upstream", "", "upstream database address (required)")
	policyPath := fs.String("policy", "", "policy file to enforce (default: allow everything)")
	startupTimeout := fs.Duration("startup-timeout", 10*time.Second, "startup phase limit (negative to disable)")
	drainTimeout := fs.Duration("drain-timeout", 30*time.Second, "shutdown drain window (0 = wait forever)")
	maxConns := fs.Int("max-conns", 1024, "max concurrent sessions (0 = unlimited)")
	writeStallTimeout := fs.Duration("write-stall-timeout", 30*time.Second,
		"tear down sessions whose client stops draining writes (negative to disable)")

	if err := fs.Parse(args); err != nil {
		return exit.Usage
	}

	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tapaside: unexpected argument %q\n", fs.Arg(0))
		fmt.Fprintln(stderr, "Run 'tapaside proxy --help' for usage.")

		return exit.Usage
	}

	if *upstream == "" {
		fmt.Fprintln(stderr, "tapaside: --upstream is required")
		fmt.Fprintln(stderr, "Run 'tapaside proxy --help' for usage.")

		return exit.Usage
	}

	if _, _, err := net.SplitHostPort(*upstream); err != nil {
		fmt.Fprintf(stderr, "tapaside: invalid --upstream %q: %v\n", *upstream, err)
		fmt.Fprintln(stderr, "Run 'tapaside proxy --help' for usage.")

		return exit.Usage
	}

	if _, _, err := net.SplitHostPort(*listen); err != nil {
		fmt.Fprintf(stderr, "tapaside: invalid --listen %q: %v\n", *listen, err)
		fmt.Fprintln(stderr, "Run 'tapaside proxy --help' for usage.")

		return exit.Usage
	}

	var pol policy.Policy
	if *policyPath != "" {
		p, err := policy.Load(*policyPath)
		if err != nil {
			fmt.Fprintf(stderr, "tapaside: %v\n", err)

			return exit.Error
		}

		// A policy file that enables no rules would silently allow every
		// query — most likely a typo or a truncated file, so say so
		// rather than start a proxy that enforces nothing.
		if !p.Enforces() {
			fmt.Fprintf(stderr, "tapaside: warning: %s enables no rules; all queries will be allowed\n", *policyPath)
		}

		pol = p
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", *listen)
	if err != nil {
		fmt.Fprintf(stderr, "tapaside: %v\n", err)

		return exit.Error
	}

	fmt.Fprintf(stdout, "tapaside proxy listening on %s, upstream %s\n", l.Addr(), *upstream)

	srv := proxy.Server{
		Upstream:          *upstream,
		Handler:           pg.Handler{StartupTimeout: *startupTimeout, Policy: pol},
		Log:               stderr,
		MaxConns:          *maxConns,
		DrainTimeout:      *drainTimeout,
		WriteStallTimeout: *writeStallTimeout,
	}
	if err := srv.Serve(ctx, l); err != nil {
		fmt.Fprintf(stderr, "tapaside: %v\n", err)

		return exit.Error
	}

	return exit.OK
}

func printProxyUsage(w io.Writer) {
	fmt.Fprintln(w, "tapaside proxy — run the sidecar proxy in front of PostgreSQL.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "USAGE:")
	fmt.Fprintln(w, "  tapaside proxy --upstream <addr> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Listens on loopback for plaintext client connections and relays each")
	fmt.Fprintln(w, "session to the upstream database, enforcing --policy on each query before")
	fmt.Fprintln(w, "it reaches the database. Enforcement covers simple queries and the extended")
	fmt.Fprintln(w, "query protocol (prepared statements); fast-path function calls are refused")
	fmt.Fprintln(w, "while a policy is active. With no policy the proxy is a transparent relay.")
	fmt.Fprintln(w, "The upstream connection is currently plaintext TCP; TLS (verify-full) is")
	fmt.Fprintln(w, "planned.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "FLAGS:")
	fmt.Fprintln(w, "  --listen <addr>          Address to listen on (default: 127.0.0.1:5433)")
	fmt.Fprintln(w, "  --upstream <addr>        Upstream database address (required)")
	fmt.Fprintln(w, "  --policy <file>          Policy file to enforce (default: allow everything)")
	fmt.Fprintln(w, "  --startup-timeout <dur>  Startup phase limit; negative to disable (default: 10s)")
	fmt.Fprintln(w, "  --drain-timeout <dur>    Shutdown wait, at most twice: graceful, then after a forced")
	fmt.Fprintln(w, "                           close; 0 = wait forever, never force (default: 30s)")
	fmt.Fprintln(w, "  --max-conns <n>          Max concurrent sessions; 0 = unlimited (default: 1024)")
	fmt.Fprintln(w, "  --write-stall-timeout <dur>  Tear down a session when a write to its client makes")
	fmt.Fprintln(w, "                           no progress for this long; negative to disable (default: 30s)")
	fmt.Fprintln(w, "  --help, -h               Show this help")
}
