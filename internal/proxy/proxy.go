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
	"runtime/debug"
	"sync"
	"syscall"
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
	// Log receives connection-level error lines. Sessions write to it
	// concurrently, so it must be safe for concurrent use (os.File is).
	// Nil disables logging.
	Log io.Writer
	// MaxConns caps concurrent sessions; connections beyond the cap are
	// closed as soon as they are accepted. Zero means no limit.
	MaxConns int
	// DrainTimeout bounds how long Serve waits for in-flight sessions
	// after shutdown. When it elapses, session contexts are canceled and
	// their connections closed to unblock relay I/O, and Serve waits up
	// to DrainTimeout once more before abandoning what is left. Zero
	// means wait forever and never force-close.
	DrainTimeout time.Duration
}

// Serve accepts connections on l until ctx is canceled or the listener
// is closed; both count as a clean shutdown. Temporary accept failures
// (e.g., file descriptor exhaustion) are retried with backoff instead
// of stopping the proxy. Cancellation closes the listener; in-flight
// sessions run detached from ctx so they are not interrupted, and
// Serve returns only after they finish or DrainTimeout elapses.
func (s Server) Serve(ctx context.Context, l net.Listener) error {
	if s.Handler == nil {
		return errors.New("proxy: nil handler")
	}

	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()

	// Sessions are detached from ctx so shutdown does not interrupt
	// them, but keep a handle to cancel them if draining times out.
	sessCtx, cancelSessions := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelSessions()

	var (
		sessions  sync.WaitGroup
		sem       chan struct{}
		delay     time.Duration
		acceptErr error

		mu    sync.Mutex
		conns = make(map[net.Conn]struct{})
	)

	if s.MaxConns > 0 {
		sem = make(chan struct{}, s.MaxConns)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}

			// The runtime already retries EINTR and ECONNABORTED inside
			// Accept, and no deadline is set on the listener; what still
			// reaches us as transient is resource exhaustion (descriptors,
			// kernel buffers, memory).
			if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
				errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay = min(delay*2, time.Second)
				}

				s.logf("accept: %v; retrying in %v\n", err, delay)

				// On cancellation the next Accept reports net.ErrClosed.
				select {
				case <-time.After(delay):
				case <-ctx.Done():
				}

				continue
			}

			acceptErr = fmt.Errorf("proxy: accept: %w", err)

			break
		}

		delay = 0

		if sem != nil {
			select {
			case sem <- struct{}{}:
			default:
				s.logf("session %s: rejected: connection limit %d reached\n", conn.RemoteAddr(), s.MaxConns)
				_ = conn.Close()

				continue
			}
		}

		mu.Lock()
		conns[conn] = struct{}{}
		mu.Unlock()

		sessions.Go(func() {
			defer func() {
				mu.Lock()
				delete(conns, conn)
				mu.Unlock()
			}()

			if sem != nil {
				defer func() { <-sem }()
			}

			s.handle(sessCtx, conn)
		})
	}

	if s.drain(&sessions) {
		return acceptErr
	}

	s.logf("shutdown: sessions still running after %v; closing their connections\n", s.DrainTimeout)
	cancelSessions()

	mu.Lock()
	for conn := range conns {
		_ = conn.Close()
	}
	mu.Unlock()

	if !s.drain(&sessions) {
		s.logf("shutdown: sessions still running after forced close; abandoning them\n")
	}

	return acceptErr
}

// drain waits for in-flight sessions and reports false when
// DrainTimeout elapses first.
func (s Server) drain(sessions *sync.WaitGroup) bool {
	done := make(chan struct{})

	go func() {
		sessions.Wait()
		close(done)
	}()

	if s.DrainTimeout <= 0 {
		<-done

		return true
	}

	select {
	case <-done:
		return true
	case <-time.After(s.DrainTimeout):
		return false
	}
}

func (s Server) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	defer func() {
		if r := recover(); r != nil {
			s.logf("session %s: panic: %v\n%s", conn.RemoteAddr(), r, debug.Stack())
		}
	}()

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
