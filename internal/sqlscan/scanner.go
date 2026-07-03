package sqlscan

import "strings"

// scanner walks SQL one byte at a time, tracking whether the cursor is
// inside a construct where SQL syntax (semicolons, keywords) must be
// ignored: string literals, quoted identifiers, dollar-quoted strings,
// and comments.
type scanner struct {
	src string
	pos int
}

// atTopLevel reports whether the cursor sits outside every quoting and
// comment construct, i.e. where a semicolon truly ends a statement.
func (s *scanner) atTopLevel() bool { return !s.inSkippable() }

// inSkippable reports whether the byte at the cursor begins, or lies
// within, a construct whose contents are not SQL syntax.
func (s *scanner) inSkippable() bool {
	return s.skippableLen() > 0
}

// advance moves the cursor forward: past a whole skippable construct if
// one starts here, otherwise by a single byte.
func (s *scanner) advance() {
	if n := s.skippableLen(); n > 0 {
		s.pos += n

		return
	}

	s.pos++
}

// skippableLen returns the byte length of the skippable construct that
// starts at the cursor, or 0 if a normal SQL byte is there.
func (s *scanner) skippableLen() int {
	rest := s.src[s.pos:]

	switch {
	case strings.HasPrefix(rest, "--"):
		return lineCommentLen(rest)
	case strings.HasPrefix(rest, "/*"):
		return blockCommentLen(rest)
	case rest[0] == '\'':
		return singleQuoteLen(rest)
	case rest[0] == '"':
		return quotedIdentLen(rest)
	case (rest[0] == 'e' || rest[0] == 'E') && len(rest) > 1 && rest[1] == '\'':
		// E'...' escape-string: backslashes escape the closing quote.
		return 1 + escapeStringLen(rest[1:])
	}

	if tag, ok := dollarTag(rest); ok {
		return dollarQuoteLen(rest, tag)
	}

	return 0
}

// lineCommentLen spans "--" through the end of the line (the newline is
// left for the caller so it still separates tokens).
func lineCommentLen(rest string) int {
	if i := strings.IndexByte(rest, '\n'); i >= 0 {
		return i
	}

	return len(rest)
}

// blockCommentLen spans "/* ... */", honoring PostgreSQL's nesting.
func blockCommentLen(rest string) int {
	depth := 0
	i := 0

	for i < len(rest) {
		switch {
		case strings.HasPrefix(rest[i:], "/*"):
			depth++
			i += 2
		case strings.HasPrefix(rest[i:], "*/"):
			depth--
			i += 2

			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}

	return len(rest) // unterminated: consume the remainder
}

// singleQuoteLen spans a '...' literal, where ” is an escaped quote.
func singleQuoteLen(rest string) int {
	for i := 1; i < len(rest); i++ {
		if rest[i] != '\'' {
			continue
		}

		if i+1 < len(rest) && rest[i+1] == '\'' {
			i++ // doubled quote: stay inside the literal

			continue
		}

		return i + 1
	}

	return len(rest)
}

// quotedIdentLen spans a "..." identifier, where "" is an escaped quote.
func quotedIdentLen(rest string) int {
	for i := 1; i < len(rest); i++ {
		if rest[i] != '"' {
			continue
		}

		if i+1 < len(rest) && rest[i+1] == '"' {
			i++

			continue
		}

		return i + 1
	}

	return len(rest)
}

// escapeStringLen spans a '...' literal where a backslash escapes the
// next byte (PostgreSQL escape-string syntax). rest starts at the
// opening quote.
func escapeStringLen(rest string) int {
	for i := 1; i < len(rest); i++ {
		switch rest[i] {
		case '\\':
			i++ // skip the escaped byte
		case '\'':
			if i+1 < len(rest) && rest[i+1] == '\'' {
				i++

				continue
			}

			return i + 1
		}
	}

	return len(rest)
}

// dollarTag returns the tag of a dollar-quote opening at the start of
// rest ("$$" -> "", "$tag$" -> "tag"), reporting false when rest does
// not open one.
func dollarTag(rest string) (string, bool) {
	if len(rest) == 0 || rest[0] != '$' {
		return "", false
	}

	for i := 1; i < len(rest); i++ {
		c := rest[i]
		if c == '$' {
			return rest[:i+1], true
		}
		if !isWordByte(c) {
			return "", false
		}
	}

	return "", false
}

// dollarQuoteLen spans a dollar-quoted string opened by tag ("$tag$").
func dollarQuoteLen(rest, tag string) int {
	if end := strings.Index(rest[len(tag):], tag); end >= 0 {
		return len(tag) + end + len(tag)
	}

	return len(rest) // unterminated: consume the remainder
}
