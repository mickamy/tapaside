package cli_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mickamy/tapaside/internal/cli"
	"github.com/mickamy/tapaside/internal/exit"
)

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "no args prints usage",
			args:       nil,
			wantCode:   exit.Usage,
			wantStderr: "USAGE:",
		},
		{
			name:       "unknown command",
			args:       []string{"serve"},
			wantCode:   exit.Usage,
			wantStderr: "unknown command",
		},
		{
			name:       "subcommand help",
			args:       []string{"proxy", "--help"},
			wantCode:   exit.OK,
			wantStdout: "tapaside proxy",
		},
		{
			name:       "subcommand help with single dash",
			args:       []string{"proxy", "-help"},
			wantCode:   exit.OK,
			wantStdout: "tapaside proxy",
		},
		{
			name:       "subcommand not implemented",
			args:       []string{"audit", "tail"},
			wantCode:   exit.NotImplemented,
			wantStderr: "not implemented",
		},
		{
			name:       "policy unknown subcommand",
			args:       []string{"policy", "frobnicate"},
			wantCode:   exit.Usage,
			wantStderr: "unknown policy command",
		},
		{
			name:       "policy check requires a file",
			args:       []string{"policy", "check"},
			wantCode:   exit.Usage,
			wantStderr: "exactly one file",
		},
		{
			name:       "policy check missing file",
			args:       []string{"policy", "check", "/nonexistent/policy.yaml"},
			wantCode:   exit.Error,
			wantStderr: "policy:",
		},
		{
			name:       "proxy requires upstream",
			args:       []string{"proxy"},
			wantCode:   exit.Usage,
			wantStderr: "--upstream is required",
		},
		{
			name:       "proxy rejects unknown flag",
			args:       []string{"proxy", "--nope"},
			wantCode:   exit.Usage,
			wantStderr: "flag provided but not defined",
		},
		{
			name:       "proxy rejects malformed listen address",
			args:       []string{"proxy", "--upstream", "127.0.0.1:5432", "--listen", "definitely-not-an-address"},
			wantCode:   exit.Usage,
			wantStderr: "invalid --listen",
		},
		{
			name:       "proxy reports unbindable listen address",
			args:       []string{"proxy", "--upstream", "127.0.0.1:5432", "--listen", "256.256.256.256:5433"},
			wantCode:   exit.Error,
			wantStderr: "tapaside:",
		},
		{
			name:       "proxy rejects extra positional arguments",
			args:       []string{"proxy", "--upstream", "127.0.0.1:5432", "extra"},
			wantCode:   exit.Usage,
			wantStderr: "unexpected argument",
		},
		{
			name:       "proxy rejects upstream without a port",
			args:       []string{"proxy", "--upstream", "db.internal"},
			wantCode:   exit.Usage,
			wantStderr: "invalid --upstream",
		},
		{
			name:       "proxy reports missing policy file",
			args:       []string{"proxy", "--upstream", "127.0.0.1:5432", "--policy", "/nonexistent/policy.yaml"},
			wantCode:   exit.Error,
			wantStderr: "policy:",
		},
		{
			name:       "proxy rejects invalid startup timeout",
			args:       []string{"proxy", "--upstream", "127.0.0.1:5432", "--startup-timeout", "abc"},
			wantCode:   exit.Usage,
			wantStderr: "invalid value",
		},
		{
			name:       "proxy rejects invalid max conns",
			args:       []string{"proxy", "--upstream", "127.0.0.1:5432", "--max-conns", "many"},
			wantCode:   exit.Usage,
			wantStderr: "invalid value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			got := cli.Run(tt.args, &stdout, &stderr)

			if got != tt.wantCode {
				t.Errorf("Run() = %d, want %d", got, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

// addrCapture extracts the listen address from the proxy's startup
// line ("tapaside proxy listening on <addr>, upstream ...").
type addrCapture struct {
	ch chan string
}

func (a *addrCapture) Write(p []byte) (int, error) {
	if _, rest, ok := strings.Cut(string(p), "listening on "); ok {
		if addr, _, ok := strings.Cut(rest, ","); ok && addr != "" {
			select {
			case a.ch <- addr:
			default:
			}
		}
	}

	return len(p), nil
}

func TestRunProxy_WarnsOnPolicyWithNoRules(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("read_only: false\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	var stdout, stderr bytes.Buffer

	// An unbindable listen address makes runProxy return after loading
	// the policy, so the warning is observable without starting a server.
	code := cli.Run(
		[]string{"proxy", "--upstream", "127.0.0.1:5432", "--listen", "256.256.256.256:5433", "--policy", path},
		&stdout, &stderr,
	)

	if code != exit.Error {
		t.Errorf("Run() = %d, want %d", code, exit.Error)
	}
	if !strings.Contains(stderr.String(), "enables no rules") {
		t.Errorf("stderr = %q, want a no-rules warning", stderr.String())
	}
}

func TestRunProxy_StartupTimeoutWiring(t *testing.T) {
	t.Parallel()

	addrCh := make(chan string, 1)

	// runProxy only returns on a signal, so this goroutine outlives the
	// test and is reclaimed at process exit.
	go func() {
		_ = cli.Run(
			[]string{"proxy", "--listen", "127.0.0.1:0", "--upstream", "127.0.0.1:1", "--startup-timeout", "50ms"},
			&addrCapture{ch: addrCh}, io.Discard,
		)
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not report its listen address")
	}

	var d net.Dialer

	conn, err := d.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	// Send nothing: the 50ms startup timeout must close the connection
	// well before the 5s guard, proving the flag reached the handler.
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("read = %v, want io.EOF from the startup timeout", err)
	}
}

func TestRunPolicyCheck_ValidFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("read_only: true\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	var stdout, stderr bytes.Buffer

	code := cli.Run([]string{"policy", "check", path}, &stdout, &stderr)

	if code != exit.OK {
		t.Errorf("Run() = %d, want %d (stderr: %s)", code, exit.OK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ok") {
		t.Errorf("stdout = %q, want it to report ok", stdout.String())
	}
}

func TestRunPolicyCheck_WarnsOnNoRules(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("read_only: false\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	var stdout, stderr bytes.Buffer

	code := cli.Run([]string{"policy", "check", path}, &stdout, &stderr)

	if code != exit.OK {
		t.Errorf("Run() = %d, want %d", code, exit.OK)
	}
	if !strings.Contains(stderr.String(), "enables no rules") {
		t.Errorf("stderr = %q, want a no-rules warning", stderr.String())
	}
}

func TestPrintUsage(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	cli.PrintUsage(&buf)

	out := buf.String()
	for _, want := range []string{"proxy", "policy", "audit"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage missing %q", want)
		}
	}
}
