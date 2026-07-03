// Package policy loads and evaluates the access policy the sidecar
// enforces locally, before a query reaches the database.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/mickamy/tapaside/internal/sqlscan"
)

// Decision is the outcome of evaluating a query against the policy.
type Decision int

const (
	// Allowed permits the query to reach the database.
	Allowed Decision = iota
	// Blocked stops the query; the proxy replies with an error instead.
	Blocked
)

// Result carries a decision and, when blocked, the rule that blocked it.
type Result struct {
	Decision Decision
	// Rule identifies the matched rule. It appears in the error returned
	// to the client and will feed audit records once those exist. Empty
	// when the query was allowed.
	Rule string
}

// Policy is the set of rules evaluated for every query. The zero value
// allows everything.
type Policy struct {
	// ReadOnly blocks any statement that is not a pure read.
	ReadOnly bool `yaml:"read_only"`
}

// Load reads and parses a policy file. Unknown fields are rejected so a
// typo like "reed_only" fails loudly instead of silently disabling a
// rule.
func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is an operator-supplied config file, not attacker input
	if err != nil {
		return Policy{}, fmt.Errorf("policy: read %s: %w", path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var p Policy
	// An empty file decodes to io.EOF; treat it as the zero-value policy.
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return Policy{}, fmt.Errorf("policy: parse %s: %w", path, err)
	}

	return p, nil
}

// Enforces reports whether the policy would block anything. When it
// does not, the proxy relays a session untouched; when it does, the
// proxy must also refuse messages it cannot evaluate (fail-closed)
// rather than let them bypass an active rule.
func (p Policy) Enforces() bool {
	return p.ReadOnly
}

// Evaluate decides whether the given SQL may proceed.
func (p Policy) Evaluate(sql string) Result {
	if p.ReadOnly && !sqlscan.ReadOnly(sql) {
		return Result{Decision: Blocked, Rule: "read_only"}
	}

	return Result{Decision: Allowed}
}
