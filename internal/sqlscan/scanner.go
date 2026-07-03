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
	case (rest[0] == 'e' || rest[0] == 'E') && len(rest) > 1 && rest[1] == '\'' && s.atTokenStart():
		// E'...' escape-string: backslashes escape the closing quote.
		// Only at a token start, so the E of LIKE'...' is not mistaken
		// for an escape-string prefix.
		return 1 + escapeStringLen(rest[1:])
	}

	// A dollar-quote opens only at a token start; otherwise a bare $ is a
	// positional parameter ($1) or part of an identifier.
	if s.atTokenStart() {
		if tag, ok := dollarTag(rest); ok {
			return dollarQuoteLen(rest, tag)
		}
	}

	return 0
}

// atTokenStart reports whether the byte at the cursor begins a new
// token, i.e. the previous byte is absent or is not an identifier byte.
func (s *scanner) atTokenStart() bool {
	return s.pos == 0 || !isWordByte(s.src[s.pos-1])
}

// lineCommentLen spans "--" up to the end of the line. PostgreSQL ends
// a line comment at either CR or LF, so both are stops; the terminator
// is left for the caller so it still separates tokens.
func lineCommentLen(rest string) int {
	if i := strings.IndexAny(rest, "\r\n"); i >= 0 {
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
		// A tag may not start with a digit; PostgreSQL reads $1 as a
		// positional parameter, not a dollar-quote opening.
		if !isWordByte(c) || (i == 1 && c >= '0' && c <= '9') {
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
