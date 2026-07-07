package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// stallChunk bounds how many bytes ride on one write deadline. Each
// chunk gets a fresh window, so the guard measures stalled progress,
// not total transfer time: a peer accepting at least one chunk per
// window survives arbitrarily large transfers, while one that stops
// draining fails within a single window.
const stallChunk = 64 << 10

// stallConn wraps the client connection so that every write must make
// progress within timeout. Reads stay untouched — long read idle is
// legitimate (connection pools) — but a peer that leaves bytes it is
// owed undrained has abandoned the session: without this guard, a
// client that stops reading pins its session goroutines, its
// connection slot, and the upstream connection forever, since relay
// writes have no deadline of their own. The upstream side is not
// wrapped; it is the operator's own database, not an untrusted peer.
type stallConn struct {
	net.Conn

	timeout time.Duration
}

// Write writes p in chunks, arming a fresh deadline per chunk.
func (c stallConn) Write(p []byte) (int, error) {
	var n int

	for len(p) > 0 {
		chunk := min(len(p), stallChunk)

		if err := c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
			return n, fmt.Errorf("proxy: set write deadline: %w", err)
		}

		m, err := c.Conn.Write(p[:chunk])
		n += m

		if err != nil {
			return n, c.stallError(err)
		}
		if m < chunk {
			// A conforming net.Conn never reports a short write without
			// an error; refuse to spin on one that does.
			return n, io.ErrShortWrite
		}

		p = p[m:]
	}

	return n, nil
}

// ReadFrom copies r to the connection in chunks, arming a fresh
// deadline per chunk like Write. Delegating each chunk to the
// underlying connection keeps its zero-copy path (splice on Linux)
// available to io.Copy.
func (c stallConn) ReadFrom(r io.Reader) (int64, error) {
	var n int64

	for {
		// Chunks never exceed what a bounded source has left, so the
		// generic copy under io.CopyN sizes its buffer to the remainder
		// (io.Copy's LimitedReader awareness), not to a full chunk.
		chunk := int64(stallChunk)
		if l, ok := r.(*io.LimitedReader); ok {
			if l.N <= 0 {
				return n, nil // the source is drained
			}

			chunk = min(chunk, l.N)
		}

		if err := c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
			return n, fmt.Errorf("proxy: set write deadline: %w", err)
		}

		m, err := io.CopyN(c.Conn, r, chunk)
		n += m

		if err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil // the source is drained
			}

			return n, c.stallError(err)
		}
	}
}

// stallError labels a deadline expiry as the stall it is, so the
// session log names the peer's behavior rather than a bare timeout;
// other errors pass through.
func (c stallConn) stallError(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("proxy: write stalled for %v: %w", c.timeout, err)
	}

	return err
}
