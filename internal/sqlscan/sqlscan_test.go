package sqlscan_test

import (
	"slices"
	"testing"

	"github.com/mickamy/tapaside/internal/sqlscan"
)

func TestReadOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sql  string
		want bool
	}{
		// Reads.
		{name: "select", sql: "SELECT 1", want: true},
		{name: "select lowercase", sql: "select * from users", want: true},
		{name: "select leading whitespace", sql: "   \n\t SELECT 1", want: true},
		{name: "show", sql: "SHOW search_path", want: true},
		{name: "values", sql: "VALUES (1), (2)", want: true},
		{name: "table", sql: "TABLE users", want: true},
		{name: "explain select", sql: "EXPLAIN SELECT 1", want: true},
		{name: "cte select", sql: "WITH t AS (SELECT 1) SELECT * FROM t", want: true},
		{name: "empty", sql: "", want: true},
		{name: "whitespace only", sql: "   \n  ", want: true},
		{name: "comment only", sql: "-- just a comment", want: true},
		{name: "block comment only", sql: "/* nothing here */", want: true},
		{name: "trailing semicolon", sql: "SELECT 1;", want: true},
		{name: "multiple reads", sql: "SELECT 1; SELECT 2;", want: true},
		{name: "leading line comment", sql: "-- note\nSELECT 1", want: true},
		{name: "keyword in string literal", sql: "SELECT 'delete from users'", want: true},
		{name: "keyword in quoted identifier", sql: `SELECT "insert" FROM t`, want: true},
		{name: "explain analyze select", sql: "EXPLAIN ANALYZE SELECT 1", want: true},

		// Writes.
		{name: "insert", sql: "INSERT INTO users VALUES (1)", want: false},
		{name: "update", sql: "UPDATE users SET x = 1", want: false},
		{name: "delete", sql: "DELETE FROM users", want: false},
		{name: "merge", sql: "MERGE INTO t USING s ON t.id = s.id", want: false},
		{name: "truncate", sql: "TRUNCATE users", want: false},
		{name: "drop", sql: "DROP TABLE users", want: false},
		{name: "create", sql: "CREATE TABLE t (id int)", want: false},
		{name: "alter", sql: "ALTER TABLE t ADD COLUMN c int", want: false},
		{name: "grant", sql: "GRANT ALL ON t TO alice", want: false},
		{name: "data-modifying cte", sql: "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", want: false},
		{name: "read then write", sql: "SELECT 1; DELETE FROM users", want: false},
		{name: "write then read", sql: "DELETE FROM users; SELECT 1", want: false},
		{name: "unknown verb", sql: "FROBNICATE users", want: false},
		{name: "explain analyze then insert", sql: "EXPLAIN SELECT 1; INSERT INTO t VALUES (1)", want: false},
		{name: "select into", sql: "SELECT * INTO new_table FROM old_table", want: false},

		// Injection-flavored: the write must not hide behind a comment or literal.
		{name: "write after inline comment", sql: "SELECT 1 /* x */; DELETE FROM t", want: false},
		{name: "semicolon inside literal is not a split", sql: "SELECT 'a;b'; DELETE FROM t", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := sqlscan.ReadOnly(tt.sql); got != tt.want {
				t.Errorf("ReadOnly(%q) = %v, want %v", tt.sql, got, tt.want)
			}
		})
	}
}

func TestReadOnly_SelectInto(t *testing.T) {
	t.Parallel()

	// SELECT INTO creates a table, so it must not pass a read-only gate.
	// Documented here because it is the one SELECT-prefixed write.
	sql := "SELECT x INTO t2 FROM t1"
	if sqlscan.ReadOnly(sql) {
		t.Error("SELECT INTO classified as read-only")
	}
}

func TestSplit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{name: "single", sql: "SELECT 1", want: []string{"SELECT 1"}},
		{name: "two", sql: "SELECT 1; SELECT 2", want: []string{"SELECT 1", "SELECT 2"}},
		{name: "trailing semicolon", sql: "SELECT 1;", want: []string{"SELECT 1"}},
		{name: "empty statements dropped", sql: ";;SELECT 1;;", want: []string{"SELECT 1"}},
		{name: "semicolon in literal", sql: "SELECT 'a;b'", want: []string{"SELECT 'a;b'"}},
		{name: "semicolon in quoted ident", sql: `SELECT "a;b"`, want: []string{`SELECT "a;b"`}},
		{
			name: "semicolon in line comment",
			sql:  "SELECT 1 -- a; b\n; SELECT 2",
			want: []string{"SELECT 1 -- a; b", "SELECT 2"},
		},
		{
			name: "semicolon in block comment",
			sql:  "SELECT 1 /* a; b */; SELECT 2",
			want: []string{"SELECT 1 /* a; b */", "SELECT 2"},
		},
		{name: "semicolon in dollar quote", sql: "SELECT $$a;b$$; SELECT 2", want: []string{"SELECT $$a;b$$", "SELECT 2"}},
		{
			name: "semicolon in tagged dollar quote",
			sql:  "SELECT $t$a;b$t$; SELECT 2",
			want: []string{"SELECT $t$a;b$t$", "SELECT 2"},
		},
		{name: "empty", sql: "", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := sqlscan.Split(tt.sql); !slices.Equal(got, tt.want) {
				t.Errorf("Split(%q) = %q, want %q", tt.sql, got, tt.want)
			}
		})
	}
}

func TestReadOnly_QuotingEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sql  string
		want bool
	}{
		{name: "escaped quote in literal", sql: `SELECT 'it''s fine'`, want: true},
		{name: "escape string with backslash quote", sql: `SELECT E'a\'; DELETE FROM t --'`, want: true},
		{name: "dollar quote hides write", sql: "SELECT $$ DELETE FROM t $$", want: true},
		{name: "unterminated literal", sql: "SELECT 'oops", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := sqlscan.ReadOnly(tt.sql); got != tt.want {
				t.Errorf("ReadOnly(%q) = %v, want %v", tt.sql, got, tt.want)
			}
		})
	}
}
