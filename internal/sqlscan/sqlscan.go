// Package sqlscan classifies SQL statements as read-only or not,
// without a full parser. It is deliberately conservative: anything it
// cannot confidently classify as a read counts as a write, so a
// read-only policy never lets an unrecognized statement through.
//
// Classification is lexical, so side effects behind a read shape are
// invisible to it: SELECT nextval('s'), setval, dblink_exec, or any
// volatile function called from a SELECT passes as a read. Enforcement
// that must hold against such statements needs the engine's own
// read-only mode behind the proxy (a read-only role, or
// default_transaction_read_only=on); this scanner is the fast
// pre-filter and the source of clear client-facing errors.
//
// The lexer assumes PostgreSQL syntax and must not be pointed at MySQL
// as is: MySQL block comments do not nest, MySQL executes /*! ... */
// and treats # as a line comment, and its string literals honor
// backslash escapes by default. Each of those makes the scanner skip
// bytes MySQL would execute — a read-only bypass. Making the lexer
// dialect-aware is a prerequisite for MySQL support.
package sqlscan

import (
	"iter"
	"strings"
)

// Kind is the read/write classification of a statement.
type Kind int

const (
	// Read is a statement that only observes data.
	Read Kind = iota
	// Write is a statement that may change data or schema, or that could
	// not be confidently classified as a read.
	Write
)

// readKeywords are the leading keywords of statements that only read.
// WITH is included because a CTE most often feeds a SELECT, but a
// data-modifying CTE (WITH ... INSERT/UPDATE/DELETE) exists, so WITH is
// resolved by scanning past the CTE rather than trusting the prefix.
//
// Cursor operations (DECLARE/FETCH/MOVE/CLOSE) are reads: a cursor can
// only be declared over a query, and a data-modifying body still trips
// the write-keyword scan, so allowing them lets read-only clients stream
// large results with cursors.
var readKeywords = map[string]bool{
	"select":  true,
	"show":    true,
	"values":  true,
	"table":   true,
	"declare": true,
	"fetch":   true,
	"move":    true,
	"close":   true,
}

// explainOptions are the words that make up an EXPLAIN prefix — the
// legacy ANALYZE/VERBOSE form and the parenthesized option list with its
// values. classify skips them to reach the underlying statement, since
// EXPLAIN ANALYZE executes it (so EXPLAIN ANALYZE INSERT/CREATE writes).
// The list need not be exhaustive: an unknown option word is treated as
// the underlying head, which is not a read keyword and so is refused —
// over-blocking a valid EXPLAIN, never letting a write through.
var explainOptions = map[string]bool{
	"analyze": true, "verbose": true, "costs": true, "settings": true,
	"generic_plan": true, "buffers": true, "serialize": true, "wal": true,
	"timing": true, "summary": true, "memory": true, "format": true,
	"on": true, "off": true, "true": true, "false": true,
	"text": true, "xml": true, "json": true, "yaml": true, "none": true, "binary": true,
}

// writeKeywords are keywords that force a Write verdict wherever they
// appear as a statement's operative verb, including inside a CTE. They
// are compared case-insensitively against raw substrings, so classify
// never allocates a lowercased copy of every word.
var writeKeywords = []string{"insert", "update", "delete", "merge"}

// controlKeywords are statement heads that do not modify data:
// transaction control and session configuration. A read-only policy
// permits them, matching PostgreSQL's own read-only transactions, which
// allow SET and BEGIN/COMMIT but reject data changes. Without this,
// real drivers break, since they send SET on connect and wrap reads in
// transactions. PREPARE and EXECUTE are intentionally absent: a
// prepared statement can carry a write.
var controlKeywords = map[string]bool{
	"begin":     true, // BEGIN
	"start":     true, // START TRANSACTION
	"commit":    true, // COMMIT
	"end":       true, // END = COMMIT
	"rollback":  true, // ROLLBACK
	"abort":     true, // ABORT = ROLLBACK
	"savepoint": true, // SAVEPOINT
	"release":   true, // RELEASE SAVEPOINT
	"set":       true, // SET / SET TRANSACTION / SET ROLE
	"reset":     true, // RESET
	"discard":   true, // DISCARD
}

// ReadOnly reports whether every statement in sql is safe under a
// read-only policy, i.e. none modifies data. Reads and non-modifying
// control statements (transaction control, SET) qualify; an empty
// input (only whitespace, comments, or empty statements) is read-only.
func ReadOnly(sql string) bool {
	for _, stmt := range Split(sql) {
		if classify(stmt) == Write {
			return false
		}
	}

	return true
}

// Split breaks sql into individual statements at top-level semicolons,
// ignoring semicolons inside string literals, quoted identifiers, and
// comments. Empty statements are omitted.
func Split(sql string) []string {
	var (
		stmts []string
		start int
	)

	s := scanner{src: sql}
	for s.pos < len(s.src) {
		n := s.skippableLen()
		if n == 0 && s.src[s.pos] == ';' {
			if stmt := strings.TrimSpace(s.src[start:s.pos]); stmt != "" {
				stmts = append(stmts, stmt)
			}

			s.pos++
			start = s.pos

			continue
		}

		s.pos += max(n, 1)
	}

	if stmt := strings.TrimSpace(s.src[start:]); stmt != "" {
		stmts = append(stmts, stmt)
	}

	return stmts
}

// classify determines whether a single statement is a read or a write.
// It short-circuits: a data-modifying verb (or SELECT ... INTO) returns
// Write the moment it is seen, so a multi-megabyte bulk INSERT is
// classified from its first word without scanning the payload.
//
// Words arrive as substrings of stmt (no allocation) and are compared to
// keywords with case-insensitive EqualFold. Lowercasing is limited to
// map lookups: the head once, plus each EXPLAIN option word while
// skipping the (bounded) EXPLAIN prefix — never the body of a large
// statement.
func classify(stmt string) Kind {
	head := ""
	var headStartsCTEOrSelect bool
	var sawExplain bool

	for w := range significantWords(stmt) {
		if head == "" {
			// EXPLAIN ANALYZE executes the underlying statement, so skip
			// the EXPLAIN prefix and its options to classify what actually
			// runs, rather than reading the head as "explain".
			if !sawExplain && strings.EqualFold(w, "explain") {
				sawExplain = true

				continue
			}
			if sawExplain && explainOptions[strings.ToLower(w)] {
				continue
			}

			head = w
			headStartsCTEOrSelect = strings.EqualFold(w, "select") || strings.EqualFold(w, "with")
		}

		// A data-modifying verb anywhere (e.g., inside a CTE) means write.
		if isWriteKeyword(w) {
			return Write
		}

		// SELECT ... INTO creates a table — the one read-shaped write. It
		// can sit behind a CTE (WITH ... SELECT ... INTO). INSERT ... INTO
		// is already caught by isWriteKeyword.
		if headStartsCTEOrSelect && strings.EqualFold(w, "into") {
			return Write
		}
	}

	if head == "" {
		return Read // only whitespace, comments, or empty statements
	}

	h := strings.ToLower(head)

	switch {
	case h == "with": // no write verb was found, so the CTE only reads
		return Read
	case readKeywords[h] || controlKeywords[h]:
		return Read
	default:
		return Write
	}
}

func isWriteKeyword(w string) bool {
	for _, kw := range writeKeywords {
		if strings.EqualFold(w, kw) {
			return true
		}
	}

	return false
}

// significantWords yields each word of stmt as a substring (no copy),
// skipping string literals, quoted identifiers, and comments so that a
// keyword hidden in a literal is never mistaken for an operative verb.
// Substrings avoid a per-word allocation on large statements; callers
// compare them case-insensitively. It is a sequence so callers can stop
// early once they have decided.
func significantWords(stmt string) iter.Seq[string] {
	return func(yield func(string) bool) {
		start := -1

		emit := func(end int) bool {
			if start < 0 {
				return true
			}

			w := stmt[start:end]
			start = -1

			return yield(w)
		}

		s := scanner{src: stmt}
		for s.pos < len(s.src) {
			if n := s.skippableLen(); n > 0 {
				if !emit(s.pos) {
					return
				}
				s.pos += n

				continue
			}

			if isWordByte(s.src[s.pos]) {
				if start < 0 {
					start = s.pos
				}
			} else if !emit(s.pos) {
				return
			}

			s.pos++
		}

		emit(len(s.src))
	}
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
