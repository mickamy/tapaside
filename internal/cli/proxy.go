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
	"github.com/mickamy/tapaside/internal/proxy"
	"github.com/mickamy/tapaside/internal/proxy/pg"
)

func runProxy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printProxyUsage(stderr) }

	listen := fs.String("listen", "127.0.0.1:5433", "address to listen on")
	upstream := fs.String("upstream", "", "upstream database address (required)")
	startupTimeout := fs.Duration("startup-timeout", 10*time.Second, "max time for a client to complete startup")
	drainTimeout := fs.Duration("drain-timeout", 30*time.Second, "max wait for in-flight sessions on shutdown")
	maxConns := fs.Int("max-conns", 0, "max concurrent sessions (0 = unlimited)")

	if err := fs.Parse(args); err != nil {
		return exit.Usage
	}

	if *upstream == "" {
		fmt.Fprintln(stderr, "tapaside: --upstream is required")
		fmt.Fprintln(stderr, "Run 'tapaside proxy --help' for usage.")

		return exit.Usage
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
		Upstream:     *upstream,
		Handler:      pg.Handler{StartupTimeout: *startupTimeout},
		Log:          stderr,
		MaxConns:     *maxConns,
		DrainTimeout: *drainTimeout,
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
	fmt.Fprintln(w, "session to the upstream database. Policy enforcement and audit output")
	fmt.Fprintln(w, "will land here. The upstream connection is currently plaintext TCP as")
	fmt.Fprintln(w, "well; TLS (verify-full) is planned.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "FLAGS:")
	fmt.Fprintln(w, "  --listen <addr>          Address to listen on (default: 127.0.0.1:5433)")
	fmt.Fprintln(w, "  --upstream <addr>        Upstream database address (required)")
	fmt.Fprintln(w, "  --startup-timeout <dur>  Max time for a client to complete startup (default: 10s)")
	fmt.Fprintln(w, "  --drain-timeout <dur>    Max wait for in-flight sessions on shutdown (default: 30s)")
	fmt.Fprintln(w, "  --max-conns <n>          Max concurrent sessions; 0 = unlimited (default: 0)")
	fmt.Fprintln(w, "  --help, -h               Show this help")
}
