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

	"github.com/mickamy/tapaside/internal/pgwire"
	"github.com/mickamy/tapaside/internal/proxy"
)

// maxStartupReads bounds how many startup-phase messages a client may
// send in one session: at most one SSLRequest and one GSSENCRequest
// (each denied with 'N'), then the actual startup message.
const maxStartupReads = 3

// Handler drives one PostgreSQL client connection. Policy evaluation
// and audit output will land here.
type Handler struct{}

var _ proxy.Handler = (*Handler)(nil)

// ServeConn implements proxy.Handler.
func (h Handler) ServeConn(ctx context.Context, client net.Conn, dial proxy.Dialer) error {
	clientR := bufio.NewReader(client)

	startup, err := negotiateStartup(client, clientR)
	if err != nil {
		return err
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

// relay pumps bytes in both directions until either side closes. The
// client-to-upstream direction is read message by message so that a
// policy hook can inspect queries before they reach the database; the
// upstream-to-client direction is copied verbatim.
func relay(client net.Conn, clientR io.Reader, upstream net.Conn) error {
	done := make(chan error, 2)

	// Each pump sends exactly one result to done, even when it panics;
	// the two receives below rely on that. A recovered panic is reported
	// as a session error so it kills this session, not the proxy.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("pg: relay client to upstream: panic: %v\n%s", r, debug.Stack())
			}
		}()

		done <- copyMessages(upstream, clientR)
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("pg: relay upstream to client: panic: %v\n%s", r, debug.Stack())
			}
		}()

		if _, err := io.Copy(client, upstream); err != nil {
			done <- fmt.Errorf("pg: copy upstream to client: %w", err)

			return
		}

		done <- nil
	}()

	err := <-done

	// Unblock the other direction, then wait for it so no goroutine
	// outlives the session. The first result is the causal one; the
	// error the second goroutine reports after its peer closed is noise.
	_ = client.Close()
	_ = upstream.Close()
	<-done

	return err
}

func copyMessages(dst io.Writer, src io.Reader) error {
	for {
		m, err := pgwire.ReadMessage(src)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil // client closed between messages
			}

			return fmt.Errorf("read client message: %w", err)
		}

		if _, err := m.WriteTo(dst); err != nil {
			return fmt.Errorf("forward client message: %w", err)
		}
	}
}
