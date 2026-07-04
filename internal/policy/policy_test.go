package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mickamy/tapaside/internal/policy"
)

func writePolicy(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	return path
}

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    policy.Policy
		wantErr bool
	}{
		{name: "read_only true", content: "read_only: true\n", want: policy.Policy{ReadOnly: true}},
		{name: "read_only false", content: "read_only: false\n", want: policy.Policy{ReadOnly: false}},
		{name: "empty file", content: "", want: policy.Policy{}},
		{name: "unknown field rejected", content: "reed_only: true\n", wantErr: true},
		{name: "malformed yaml", content: "read_only: [unclosed\n", wantErr: true},
		{name: "wrong type", content: "read_only: not-a-bool\n", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := policy.Load(writePolicy(t, tt.content))

			if tt.wantErr {
				if err == nil {
					t.Fatal("Load() error = nil, want error")
				}

				return
			}

			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLoad_MissingFile(t *testing.T) {
	t.Parallel()

	if _, err := policy.Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("Load() error = nil, want error for missing file")
	}
}

func TestPolicy_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pol  policy.Policy
		sql  string
		want policy.Result
	}{
		{
			name: "read-only allows select",
			pol:  policy.Policy{ReadOnly: true},
			sql:  "SELECT 1",
			want: policy.Result{Decision: policy.Allowed},
		},
		{
			name: "read-only blocks insert",
			pol:  policy.Policy{ReadOnly: true},
			sql:  "INSERT INTO t VALUES (1)",
			want: policy.Result{Decision: policy.Blocked, Rule: "read_only"},
		},
		{
			name: "read-only blocks multi-statement with a write",
			pol:  policy.Policy{ReadOnly: true},
			sql:  "SELECT 1; DELETE FROM t",
			want: policy.Result{Decision: policy.Blocked, Rule: "read_only"},
		},
		{
			name: "permissive allows insert",
			pol:  policy.Policy{},
			sql:  "INSERT INTO t VALUES (1)",
			want: policy.Result{Decision: policy.Allowed},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.pol.Evaluate(tt.sql); got != tt.want {
				t.Errorf("Evaluate(%q) = %+v, want %+v", tt.sql, got, tt.want)
			}
		})
	}
}
