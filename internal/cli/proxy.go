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
	startupTimeout := fs.Duration("startup-timeout", 10*time.Second, "startup phase limit (negative to disable)")
	drainTimeout := fs.Duration("drain-timeout", 30*time.Second, "shutdown drain window (0 = wait forever)")
	maxConns := fs.Int("max-conns", 1024, "max concurrent sessions (0 = unlimited)")

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
	fmt.Fprintln(w, "  --startup-timeout <dur>  Startup phase limit; negative to disable (default: 10s)")
	fmt.Fprintln(w, "  --drain-timeout <dur>    Shutdown wait, at most twice: graceful, then after a forced")
	fmt.Fprintln(w, "                           close; 0 = wait forever, never force (default: 30s)")
	fmt.Fprintln(w, "  --max-conns <n>          Max concurrent sessions; 0 = unlimited (default: 1024)")
	fmt.Fprintln(w, "  --help, -h               Show this help")
}
