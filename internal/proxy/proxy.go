// Package proxy implements the dialect-agnostic core of the tapaside
// sidecar: a TCP listener that hands each client connection to a
// protocol handler, which drives the conversation with the client and
// relays messages to the upstream database.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const upstreamDialTimeout = 10 * time.Second

// Dialer connects to the configured upstream database. It returns a
// plain TCP connection; upgrading to TLS is the handler's job since
// both PostgreSQL and MySQL negotiate encryption in-protocol.
type Dialer func(ctx context.Context) (net.Conn, error)

// Handler drives one client connection in a database-specific wire
// protocol. It calls dial when the dialect is ready to contact the
// upstream. The timing differs per dialect: a PostgreSQL client sends
// the first bytes (startup), while a MySQL server does (handshake),
// so only the dialect knows when the upstream connection is needed.
type Handler interface {
	ServeConn(ctx context.Context, client net.Conn, dial Dialer) error
}

// Server accepts client connections and hands each of them to Handler.
type Server struct {
	// Upstream is the address (host:port) of the database to connect to.
	Upstream string
	// Handler drives accepted connections. Required.
	Handler Handler
	// Log receives connection-level error lines. Nil disables logging.
	Log io.Writer
}

// Serve accepts connections on l until ctx is canceled or the listener
// is closed. Cancellation closes the listener; in-flight sessions are
// not interrupted.
func (s Server) Serve(ctx context.Context, l net.Listener) error {
	if s.Handler == nil {
		return errors.New("proxy: nil handler")
	}

	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return fmt.Errorf("proxy: accept: %w", err)
		}

		go s.handle(ctx, conn)
	}
}

func (s Server) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	err := s.Handler.ServeConn(ctx, conn, s.dial)
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return
	}

	s.logf("session %s: %v\n", conn.RemoteAddr(), err)
}

func (s Server) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: upstreamDialTimeout}

	conn, err := d.DialContext(ctx, "tcp", s.Upstream)
	if err != nil {
		return nil, fmt.Errorf("proxy: dial upstream %s: %w", s.Upstream, err)
	}

	return conn, nil
}

func (s Server) logf(format string, args ...any) {
	if s.Log == nil {
		return
	}

	fmt.Fprintf(s.Log, format, args...)
}
