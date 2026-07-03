// Package pg implements the PostgreSQL dialect of the tapaside proxy:
// it drives the client side of the PostgreSQL wire protocol (version 3)
// and relays messages between the client and the upstream database.
package pg

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mickamy/tapaside/internal/pgwire"
	"github.com/mickamy/tapaside/internal/policy"
	"github.com/mickamy/tapaside/internal/proxy"
)

// Transaction status bytes carried by ReadyForQuery.
const (
	txIdle   = 'I' // not in a transaction
	txActive = 'T' // in a transaction block
	txFailed = 'E' // in a failed transaction block
)

// maxStartupReads bounds how many startup-phase messages a client may
// send in one session: at most one SSLRequest and one GSSENCRequest
// (each denied with 'N'), then the actual startup message.
const maxStartupReads = 3

const defaultStartupTimeout = 10 * time.Second

// Handler drives one PostgreSQL client connection, evaluating each
// query against Policy before it reaches the database.
type Handler struct {
	// StartupTimeout bounds how long a client may take to complete the
	// startup phase, so an idle or malicious connection cannot hold a
	// session slot forever. Zero means the default of 10s; a negative
	// value disables the timeout.
	StartupTimeout time.Duration
	// Policy is evaluated for every simple query; while it enforces
	// anything, message types whose SQL cannot be evaluated (the extended
	// query protocol, fast-path calls) are refused rather than forwarded.
	// The zero value allows everything and relays transparently.
	Policy policy.Policy
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

	return relay(client, clientR, upstream, h.Policy)
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
func relay(client net.Conn, clientR io.Reader, upstream net.Conn, pol policy.Policy) error {
	done := make(chan pumpResult, 2)

	// Both directions may write to the client: the upstream copy below
	// and the synthetic responses copyMessages sends for blocked
	// queries. Serialize them so the two never interleave a write.
	clientW := &syncWriter{w: client}

	// The upstream→client pump records each ReadyForQuery status here so
	// the client→upstream pump can report the real transaction state when
	// it synthesizes a response for a blocked query.
	var txStatus atomic.Int32
	txStatus.Store(int32(txIdle))

	// Each pump sends exactly one result to done, even when it panics;
	// the receives below rely on that. A recovered panic is reported as
	// a session error so it kills this session, not the proxy.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- pumpResult{err: fmt.Errorf("pg: relay client to upstream: panic: %v\n%s", r, debug.Stack())}
			}
		}()

		halfClose, err := copyMessages(upstream, clientW, clientR, pol, &txStatus)
		done <- pumpResult{halfClose: halfClose, err: err}
	}()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- pumpResult{err: fmt.Errorf("pg: relay upstream to client: panic: %v\n%s", r, debug.Stack())}
			}
		}()

		if err := copyResponses(clientW, upstream, &txStatus); err != nil && !isDisconnect(err) {
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

// Client message types this handler inspects. See the PostgreSQL
// frontend/backend protocol for the full set.
const (
	msgParse        = 'P' // extended protocol: define a statement
	msgBind         = 'B' // extended protocol: bind a portal
	msgExecute      = 'E' // extended protocol: run a portal
	msgDescribe     = 'D' // extended protocol: describe a statement/portal
	msgClose        = 'C' // extended protocol: close a statement/portal
	msgSync         = 'S' // extended protocol: end of a message batch
	msgFunctionCall = 'F' // legacy fast-path function call
)

// copyMessages relays framed client messages to the upstream until the
// client disconnects, enforcing pol before anything reaches the
// database. A blocked simple query is answered directly on clientW with
// an ErrorResponse and a ReadyForQuery, exactly as the backend would
// after refusing a statement.
//
// The lexer can only classify the SQL text of a simple query, so when a
// policy is active the handler is fail-closed on message types it
// cannot evaluate: the extended query protocol (Parse/Bind/Execute/...)
// and fast-path function calls are refused rather than forwarded, so a
// prepared-statement client cannot slip a write past an active policy.
// Evaluating the SQL carried in Parse is a later step; until then this
// trades prepared-statement support for a boundary that does not leak.
//
// It reports halfClose only for a clean EOF on a message boundary — the
// one case where the client deliberately shut down its write side and
// may still be waiting for responses.
func copyMessages(
	upstream io.Writer,
	clientW *syncWriter,
	src io.Reader,
	pol policy.Policy,
	txStatus *atomic.Int32,
) (halfClose bool, _ error) {
	f := msgFilter{clientW: clientW, pol: pol, enforce: pol.Enforces(), txStatus: txStatus}

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

		handled, err := f.handle(m)
		if err != nil {
			if isDisconnect(err) {
				return false, nil
			}

			return false, err
		}
		if handled {
			continue
		}

		if _, err := m.WriteTo(upstream); err != nil {
			if isDisconnect(err) {
				return false, nil
			}

			return false, fmt.Errorf("forward client message: %w", err)
		}
	}
}

// msgFilter applies policy to each client message, answering blocked or
// unsupported ones directly on the client and tracking the extended
// protocol's skip-until-Sync recovery state across messages.
type msgFilter struct {
	clientW *syncWriter
	pol     policy.Policy
	enforce bool
	// txStatus is the last transaction status the backend reported, so a
	// synthesized ReadyForQuery can tell the client the truth.
	txStatus *atomic.Int32
	// skipUntilSync is set after an extended-protocol batch is refused;
	// the backend discards a failed batch until Sync, so the proxy does
	// the same, then answers with one ReadyForQuery.
	skipUntilSync bool
}

// readyStatus is the transaction status to report when synthesizing a
// ReadyForQuery for a query the proxy refused. Refusing a statement is
// an error, and in PostgreSQL an error inside a transaction aborts it,
// so anything other than idle becomes failed ('E'). The client then
// rolls back, which the proxy forwards, resyncing both ends.
func (f *msgFilter) readyStatus() byte {
	if f.txStatus.Load() == int32(txIdle) {
		return txIdle
	}

	return txFailed
}

// handle returns handled=true when the message was answered locally (a
// blocked query, a refused extended-protocol message, or one swallowed
// during skip-until-sync) and must not be forwarded upstream.
func (f *msgFilter) handle(m pgwire.Message) (bool, error) {
	if f.skipUntilSync {
		if m.Type == msgSync {
			f.skipUntilSync = false

			return true, f.clientW.writeMessage(pgwire.ReadyForQuery(f.readyStatus()))
		}

		return true, nil // discard everything until the batch ends
	}

	if m.IsQuery() {
		if res := f.pol.Evaluate(m.QueryText()); res.Decision == policy.Blocked {
			return true, f.denyQuery(res)
		}

		return false, nil
	}

	if !f.enforce {
		return false, nil
	}

	switch m.Type {
	case msgParse, msgBind, msgExecute, msgDescribe, msgClose:
		// Refuse the whole batch, then swallow up to its Sync.
		f.skipUntilSync = true

		return true, f.clientW.writeMessage(pgwire.ErrorResponse("0A000", extendedNotSupported))
	case msgFunctionCall:
		// Fast-path is not followed by Sync; answer it on its own.
		return true, f.clientW.writeMessages(
			pgwire.ErrorResponse("0A000", fastPathNotSupported),
			pgwire.ReadyForQuery(f.readyStatus()),
		)
	}

	return false, nil
}

const (
	extendedNotSupported = "tapaside: the extended query protocol is not supported while a policy is active; " +
		"use the simple query protocol"
	fastPathNotSupported = "tapaside: fast-path function calls are not supported while a policy is active"
)

// denyQuery answers a blocked simple query the way the backend answers a
// rejected statement: an ErrorResponse followed by ReadyForQuery so the
// client leaves its busy state and can send the next query.
func (f *msgFilter) denyQuery(res policy.Result) error {
	// 42501 is insufficient_privilege, the closest standard SQLSTATE for
	// "the gateway refused this", and one clients surface as a normal
	// permission error rather than a connection fault. The ErrorResponse
	// and ReadyForQuery go out together so nothing can split the pair.
	msg := fmt.Sprintf("blocked by tapaside policy (%s)", res.Rule)

	return f.clientW.writeMessages(pgwire.ErrorResponse("42501", msg), pgwire.ReadyForQuery(f.readyStatus()))
}

// copyResponses relays backend messages to the client, forwarding each
// verbatim while recording the transaction status from every
// ReadyForQuery so the client→upstream pump can report it on a blocked
// query. Message payloads are streamed rather than buffered, so a large
// result set does not grow memory; only the tiny ReadyForQuery is read
// whole to capture its status byte.
func copyResponses(clientW *syncWriter, upstream io.Reader, txStatus *atomic.Int32) error {
	var header [5]byte

	for {
		if _, err := io.ReadFull(upstream, header[:]); err != nil {
			return fmt.Errorf("read backend message header: %w", err)
		}

		length := binary.BigEndian.Uint32(header[1:5])
		if length < 4 {
			return fmt.Errorf("pg: invalid backend message length %d", length)
		}

		payloadLen := int64(length) - 4

		// ReadyForQuery is 'Z' + int32(5) + one status byte. Capture the
		// status and forward the whole 6-byte message in one write.
		if header[0] == 'Z' && payloadLen == 1 {
			var status [1]byte
			if _, err := io.ReadFull(upstream, status[:]); err != nil {
				return fmt.Errorf("read ready-for-query status: %w", err)
			}

			txStatus.Store(int32(status[0]))

			if _, err := clientW.Write([]byte{header[0], header[1], header[2], header[3], header[4], status[0]}); err != nil {
				return fmt.Errorf("forward ready-for-query: %w", err)
			}

			continue
		}

		if _, err := clientW.Write(header[:]); err != nil {
			return fmt.Errorf("forward backend header: %w", err)
		}
		if payloadLen > 0 {
			if _, err := io.CopyN(clientW, upstream, payloadLen); err != nil {
				return fmt.Errorf("forward backend payload: %w", err)
			}
		}
	}
}

// syncWriter serializes concurrent writes to the client connection.
// Both relay directions target it: the raw upstream→client copy and the
// synthetic responses for blocked queries. Its lock keeps them from
// interleaving.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// Write serializes a raw byte slice from the upstream→client copy.
func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.w.Write(p) //nolint:wrapcheck // thin serializing wrapper; callers wrap with context
}

// writeMessage writes one protocol message in a single locked Write.
func (w *syncWriter) writeMessage(m pgwire.Message) error {
	return w.writeMessages(m)
}

// writeMessages writes the given messages back to back in one locked
// Write, so no concurrent upstream bytes can land between them — neither
// inside a single message (Message.WriteTo cannot promise this, since on
// a plain io.Writer net.Buffers falls back to one Write per buffer) nor
// between the two messages of a deny response.
func (w *syncWriter) writeMessages(msgs ...pgwire.Message) error {
	var buf []byte
	for _, m := range msgs {
		buf = append(buf, m.Bytes()...)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := w.w.Write(buf); err != nil {
		return fmt.Errorf("pg: write client messages: %w", err)
	}

	return nil
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
