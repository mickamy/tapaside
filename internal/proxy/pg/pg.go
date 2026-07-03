// Package pg implements the PostgreSQL dialect of the tapaside proxy:
// it drives the client side of the PostgreSQL wire protocol (version 3)
// and relays messages between the client and the upstream database.
package pg

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/mickamy/tapaside/internal/pgwire"
	"github.com/mickamy/tapaside/internal/proxy"
)

// maxStartupReads bounds how many startup-phase messages a client may
// send in one session: at most one SSLRequest and one GSSENCRequest
// (each denied with 'N'), then the actual startup message.
const maxStartupReads = 3

const defaultStartupTimeout = 10 * time.Second

// Handler drives one PostgreSQL client connection. Policy evaluation
// and audit output will land here.
type Handler struct {
	// StartupTimeout bounds how long a client may take to complete the
	// startup phase, so an idle or malicious connection cannot hold a
	// session slot forever. Zero means the default of 10s; a negative
	// value disables the timeout.
	StartupTimeout time.Duration
}

var _ proxy.Handler = (*Handler)(nil)

// ServeConn implements proxy.Handler.
func (h Handler) ServeConn(ctx context.Context, client net.Conn, dial proxy.Dialer) error {
	timeout := h.StartupTimeout
	if timeout == 0 {
		timeout = defaultStartupTimeout
	}

	if timeout > 0 {
		if err := client.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("pg: set startup deadline: %w", err)
		}
	}

	clientR := bufio.NewReader(client)

	startup, err := negotiateStartup(client, clientR)
	if err != nil {
		return err
	}

	// The startup phase is over; established sessions may legitimately
	// idle for a long time (connection pools), so no relay deadline.
	if err := client.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("pg: clear startup deadline: %w", err)
	}

	upstream, err := dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = upstream.Close() }()

	if _, err := startup.WriteTo(upstream); err != nil {
		return fmt.Errorf("forward startup: %w", err)
	}

	if startup.IsCancelRequest() {
		// A cancel request has no response; the server just closes.
		return nil
	}

	return relay(client, clientR, upstream)
}

// negotiateStartup reads startup-phase messages from the client until
// it sends one the proxy can forward. Encryption requests are denied
// with 'N' since the client side of the sidecar is plaintext by design.
func negotiateStartup(client io.Writer, clientR io.Reader) (pgwire.StartupMessage, error) {
	for range maxStartupReads {
		m, err := pgwire.ReadStartup(clientR)
		if err != nil {
			return pgwire.StartupMessage{}, fmt.Errorf("read client startup: %w", err)
		}

		if !m.IsSSLRequest() && !m.IsGSSEncRequest() {
			return m, nil
		}

		if _, err := client.Write([]byte{'N'}); err != nil {
			return pgwire.StartupMessage{}, fmt.Errorf("pg: deny encryption request: %w", err)
		}
	}

	return pgwire.StartupMessage{}, errors.New("pg: too many encryption requests")
}

// closeWriter is the half-close capability of *net.TCPConn and
// *tls.Conn: shut down the write side while reads keep working.
type closeWriter interface {
	CloseWrite() error
}

type pumpResult struct {
	// halfClose is set only by the client-to-upstream pump, when the
	// client closed its write side cleanly on a message boundary and
	// may still be waiting for responses. Abrupt disconnects (reset,
	// mid-message EOF) never set it: that client is gone, so its
	// session is torn down instead of served out.
	halfClose bool
	err       error
}

// relay pumps bytes in both directions. The client-to-upstream
// direction is read message by message so that a policy hook can
// inspect queries before they reach the database; the
// upstream-to-client direction is copied verbatim.
//
// A client that half-closes cleanly on a message boundary may still be
// waiting for the rest of the response, so the proxy propagates the
// EOF with CloseWrite and keeps relaying; the backend closes on its own
// EOF, which bounds the wait. Any other way a session ends — abrupt
// disconnect included — the first result is the causal one: both
// connections are closed to unblock the other pump, whose late error
// is noise.
func relay(client net.Conn, clientR io.Reader, upstream net.Conn) error {
	done := make(chan pumpResult, 2)

	// Each pump sends exactly one result to done, even when it panics;
	// the receives below rely on that. A recovered panic is reported as
	// a session error so it kills this session, not the proxy.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- pumpResult{err: fmt.Errorf("pg: relay client to upstream: panic: %v\n%s", r, debug.Stack())}
			}
		}()

		halfClose, err := copyMessages(upstream, clientR)
		done <- pumpResult{halfClose: halfClose, err: err}
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- pumpResult{err: fmt.Errorf("pg: relay upstream to client: panic: %v\n%s", r, debug.Stack())}
			}
		}()

		if _, err := io.Copy(client, upstream); err != nil && !isDisconnect(err) {
			done <- pumpResult{err: fmt.Errorf("pg: copy upstream to client: %w", err)}

			return
		}

		done <- pumpResult{}
	}()

	first := <-done

	if first.halfClose {
		if cw, ok := upstream.(closeWriter); ok && cw.CloseWrite() == nil {
			second := <-done

			_ = client.Close()
			_ = upstream.Close()

			return second.err
		}
	}

	_ = client.Close()
	_ = upstream.Close()
	<-done

	return first.err
}

// copyMessages relays framed messages from src until it disconnects.
// It reports halfClose only for a clean EOF on a message boundary — the
// one case where the client deliberately shut down its write side and
// may still be waiting for responses.
func copyMessages(dst io.Writer, src io.Reader) (halfClose bool, _ error) {
	for {
		m, err := pgwire.ReadMessage(src)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return true, nil // clean half-close on a message boundary
			}
			if isDisconnect(err) {
				return false, nil // the peer went away; normal for a proxy
			}

			return false, fmt.Errorf("read client message: %w", err)
		}

		if _, err := m.WriteTo(dst); err != nil {
			if isDisconnect(err) {
				return false, nil
			}

			return false, fmt.Errorf("forward client message: %w", err)
		}
	}
}

// isDisconnect reports whether err is one of the errors a vanished or
// half-closed peer produces. During relay the proxy treats those as
// normal session termination, not failures worth logging: clients
// disconnect abruptly all the time (Ctrl+C, crashed apps, mid-message
// kills), and which relay direction observes it first is a race.
func isDisconnect(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}
