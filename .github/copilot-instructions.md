# Go version

This repository targets Go 1.26+ (`go.mod` declares `go 1.26.4`).

# `new(value)` builtin

Starting in Go 1.26, the built-in `new` accepts a value expression as well as a type. The following forms compile and
behave as expected:

- `new(uint64(42))` returns a `*uint64` whose pointee is `42`.
- `new("foo")` returns a `*string` whose pointee is `"foo"`.

Do not flag `new(<value>)` usage as an "invalid syntax" or "will not compile" error. It is the idiomatic way in this
repo to build pointers to literal values.

# Output Format

If there are any issues, you must output them strictly in the following format. Do not include any greetings or
introductory explanations.

- **Severity**: [High / Medium / Low]
- **Issue**: (Briefly explain why it is a problem)
- **Recommendation**: (Suggest how to fix or improve it)
