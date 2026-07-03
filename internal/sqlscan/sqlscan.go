// Package sqlscan classifies SQL statements as read-only or not,
// without a full parser. It is deliberately conservative: anything it
// cannot confidently classify as a read counts as a write, so a
// read-only policy never lets an unrecognized statement through.
//
// The lexer assumes PostgreSQL syntax and must not be pointed at MySQL
// as is: MySQL block comments do not nest, MySQL executes /*! ... */
// and treats # as a line comment, and its string literals honor
// backslash escapes by default. Each of those makes the scanner skip
// bytes MySQL would execute — a read-only bypass. Making the lexer
// dialect-aware is a prerequisite for MySQL support.
package sqlscan

import (
	"slices"
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
var readKeywords = map[string]bool{
	"select":  true,
	"show":    true,
	"values":  true,
	"table":   true,
	"explain": true,
}

// writeKeywords are keywords that force a Write verdict wherever they
// appear as a statement's operative verb, including inside a CTE.
var writeKeywords = map[string]bool{
	"insert": true,
	"update": true,
	"delete": true,
	"merge":  true,
}

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
func classify(stmt string) Kind {
	words := significantWords(stmt)
	if len(words) == 0 {
		return Read
	}

	head := words[0]

	// A data-modifying verb anywhere (e.g., inside a CTE) means write.
	for _, w := range words {
		if writeKeywords[w] {
			return Write
		}
	}

	// SELECT ... INTO creates a table, so it is the one read-shaped write.
	// It can sit behind a CTE (WITH ... SELECT ... INTO), so this is
	// checked before the WITH short-circuit below.
	if (head == "select" || head == "with") && slices.Contains(words, "into") {
		return Write
	}

	if head == "with" {
		// No write verb was found above, so the CTE body only reads.
		return Read
	}

	if readKeywords[head] || controlKeywords[head] {
		return Read
	}

	return Write
}

// significantWords returns the lowercased words of stmt, skipping string
// literals, quoted identifiers, and comments so that a keyword hidden in
// a literal is never mistaken for an operative verb. Keywords are ASCII,
// so bytes are lowercased in place rather than allocating with ToLower.
func significantWords(stmt string) []string {
	var (
		words []string
		word  strings.Builder
	)

	flush := func() {
		if word.Len() > 0 {
			words = append(words, word.String())
			word.Reset()
		}
	}

	s := scanner{src: stmt}
	for s.pos < len(s.src) {
		if n := s.skippableLen(); n > 0 {
			flush()
			s.pos += n

			continue
		}

		c := s.src[s.pos]
		switch {
		case c >= 'A' && c <= 'Z':
			word.WriteByte(c + ('a' - 'A'))
		case isWordByte(c):
			word.WriteByte(c)
		default:
			flush()
		}

		s.pos++
	}

	flush()

	return words
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
