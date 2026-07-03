package cli_test

import (
	"bytes"
	"strings"
	"testing"

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
			name:       "proxy rejects bad listen address",
			args:       []string{"proxy", "--upstream", "127.0.0.1:5432", "--listen", "definitely-not-an-address"},
			wantCode:   exit.Error,
			wantStderr: "tapaside:",
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
