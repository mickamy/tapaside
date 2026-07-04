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
	"slices"
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

// maxMessageLen bounds a backend message payload, mirroring PostgreSQL's
// 1 GB message limit, so a corrupted length header cannot make the proxy
// stream an unbounded amount from the upstream.
const maxMessageLen = 1 << 30

// maxHeldBytes bounds how much of an extended-protocol batch the proxy
// holds back before releasing it upstream. Holding until Sync keeps a
// denied batch invisible to the backend; a batch that outgrows the
// budget (bulk Bind parameters, deep pipelining) is released early,
// trading that invisibility for bounded memory.
const maxHeldBytes = 1 << 20

// scratchMax bounds the buffers a session retains for reuse across
// messages: the scratch that inspected payloads land in and the held
// batch buffer. Payloads above it use one-off buffers or are streamed,
// so one unusual message cannot leave every session pinning large
// memory.
const scratchMax = 64 << 10

// Handler drives one PostgreSQL client connection, evaluating each
// query against Policy before it reaches the database.
type Handler struct {
	// StartupTimeout bounds how long a client may take to complete the
	// startup phase, so an idle or malicious connection cannot hold a
	// session slot forever. Zero means the default of 10s; a negative
	// value disables the timeout.
	StartupTimeout time.Duration
	// Policy is evaluated for every simple query and for the SQL carried
	// by every extended-protocol Parse message. While it enforces
	// anything, messages whose SQL cannot be evaluated (fast-path calls,
	// a malformed Parse) are refused rather than forwarded. The zero
	// value allows everything and relays transparently.
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
		// The client is mid-startup, waiting for the server's first
		// message; a backend whose startup fails answers with a FATAL
		// error before closing, so do the same rather than vanish. A
		// cancel request expects no response at all. The dial error
		// itself goes to the server log, not to the client.
		if !startup.IsCancelRequest() {
			_, _ = pgwire.FatalResponse("08006", upstreamUnreachable).WriteTo(client)
		}

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
	msgQuery        = 'Q' // simple query
	msgParse        = 'P' // extended protocol: define a statement
	msgBind         = 'B' // extended protocol: bind a portal
	msgExecute      = 'E' // extended protocol: run a portal
	msgDescribe     = 'D' // extended protocol: describe a statement/portal
	msgClose        = 'C' // extended protocol: close a statement/portal
	msgSync         = 'S' // extended protocol: end of a message batch
	msgFlush        = 'H' // extended protocol: request the pending responses
	msgFunctionCall = 'F' // legacy fast-path function call
)

// copyMessages relays framed client messages to the upstream until the
// client disconnects, enforcing pol before anything reaches the
// database. A blocked simple query is answered directly on clientW with
// an ErrorResponse and a ReadyForQuery, exactly as the backend would
// after refusing a statement.
//
// Extended-protocol batches are evaluated at their Parse messages, the
// only ones that carry SQL. While a policy is enforced, a batch is held
// back and forwarded whole at its Sync, so a deny anywhere in the batch
// can discard it whole: the backend sees a denied batch not at all and
// the synthesized ErrorResponse/ReadyForQuery pair is the entire
// exchange. Fast-path function calls can invoke arbitrary functions and
// stay refused outright while a policy is active.
//
// Only the header of each message is read up front; the payload is then
// materialized, held, streamed, or discarded depending on what the
// filter needs from it, so a message the policy never inspects (a bulk
// CopyData, an oversized Bind) does not have to fit in memory.
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
	f := msgFilter{clientW: clientW, upstream: upstream, src: src, pol: pol, enforce: pol.Enforces(), txStatus: txStatus}

	for {
		hdr, err := pgwire.ReadHeader(src)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return true, nil // clean half-close on a message boundary
			}
			if isDisconnect(err) {
				return false, nil // the peer went away; normal for a proxy
			}

			return false, fmt.Errorf("read client message: %w", err)
		}

		if err := f.handle(hdr); err != nil {
			if isDisconnect(err) {
				return false, nil
			}

			return false, err
		}
	}
}

// msgFilter applies policy to each client message, disposing of every
// one of them: forwarded upstream, held for the current batch, or
// answered directly on the client when blocked or unsupported.
type msgFilter struct {
	clientW  *syncWriter
	upstream io.Writer
	src      io.Reader
	pol      policy.Policy
	enforce  bool
	// txStatus is the last transaction status the backend reported, so a
	// synthesized ReadyForQuery can tell the client the truth.
	txStatus *atomic.Int32
	// scratch is reused for payloads the filter materializes, so
	// steady-state traffic does not allocate per message. Its capacity
	// is capped at scratchMax.
	scratch []byte
	// heldBuf accumulates the current extended-protocol batch in wire
	// format while a policy is enforced. Forwarding a batch only at its
	// Sync keeps it all-or-nothing: a deny discards the batch whole, and
	// the backend is never left holding half a batch whose Sync will not
	// come.
	heldBuf []byte
	// prefixForwarded records that part of the current batch was already
	// released upstream (a Flush, or a batch that outgrew the hold
	// budget), so a deny can no longer pretend the batch never happened
	// and must resync through the backend instead.
	prefixForwarded bool
	// skipUntilSync is set after a batch is denied; the backend discards
	// a failed batch until Sync, so the proxy does the same.
	skipUntilSync bool
	// forwardSync chooses how a denied batch ends at its Sync: forwarded
	// upstream when the backend saw part of the batch, so its own
	// ReadyForQuery resyncs both ends, and synthesized otherwise.
	forwardSync bool
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

// handle disposes of one client message, of which only the header has
// been read: forwarded upstream, held for the current batch, answered
// locally, or discarded during deny recovery.
func (f *msgFilter) handle(hdr pgwire.Header) error {
	if f.skipUntilSync {
		if hdr.Type != msgSync {
			return f.discardPayload(hdr) // swallow until the batch ends
		}

		f.skipUntilSync = false

		if f.forwardSync {
			f.forwardSync = false
			f.prefixForwarded = false

			payload, err := f.inspectPayload(hdr)
			if err != nil {
				return err
			}

			return f.forwardBuffered(hdr, payload)
		}

		if err := f.discardPayload(hdr); err != nil {
			return err
		}

		return f.clientW.writeMessage(pgwire.ReadyForQuery(f.readyStatus()))
	}

	if !f.enforce {
		return f.relay(hdr)
	}

	switch hdr.Type {
	case msgQuery:
		payload, err := f.inspectPayload(hdr)
		if err != nil {
			return err
		}

		if err := f.flushHeld(); err != nil {
			return err
		}

		m := pgwire.Message{Type: hdr.Type, Payload: payload}
		if res := f.pol.Evaluate(m.QueryText()); res.Decision == policy.Blocked {
			return f.denyQuery(res)
		}

		return f.forwardBuffered(hdr, payload)
	case msgParse:
		payload, err := f.inspectPayload(hdr)
		if err != nil {
			return err
		}

		m := pgwire.Message{Type: hdr.Type, Payload: payload}

		sql, err := m.ParseQueryText()
		if err != nil {
			// 08P01 is protocol_violation: the backend answers a Parse it
			// cannot decode the same way.
			return f.denyBatch("08P01", malformedParse)
		}

		if res := f.pol.Evaluate(sql); res.Decision == policy.Blocked {
			return f.denyBatch("42501", fmt.Sprintf("blocked by tapaside policy (%s)", res.Rule))
		}

		return f.hold(hdr, payload)
	case msgBind, msgExecute, msgDescribe, msgClose:
		// No SQL of their own; every statement they can reference went
		// through a Parse this filter already evaluated.
		return f.holdFromWire(hdr)
	case msgSync:
		if err := f.holdFromWire(hdr); err != nil {
			return err
		}
		if err := f.flushHeld(); err != nil {
			return err
		}
		f.prefixForwarded = false // the batch is over

		return nil
	case msgFlush:
		// The client wants the responses so far; the held prefix has to
		// reach the backend for those to exist.
		if err := f.holdFromWire(hdr); err != nil {
			return err
		}

		return f.flushHeld()
	case msgFunctionCall:
		if err := f.discardPayload(hdr); err != nil {
			return err
		}

		// Fast-path is not followed by Sync; answer it on its own.
		return f.clientW.writeMessages(
			pgwire.ErrorResponse("0A000", fastPathNotSupported),
			pgwire.ReadyForQuery(f.readyStatus()),
		)
	}

	if err := f.flushHeld(); err != nil {
		return err
	}

	return f.relay(hdr)
}

const (
	fastPathNotSupported = "tapaside: fast-path function calls are not supported while a policy is active"
	malformedParse       = "tapaside: malformed Parse message"
	upstreamUnreachable  = "tapaside: upstream database is unreachable"
)

// inspectPayload reads a payload the filter must look at. Ordinary
// sizes land in the session scratch buffer, so steady-state inspection
// does not allocate; an outsized claim falls back to pgwire.ReadPayload,
// whose buffer grows only as bytes arrive and is not retained.
func (f *msgFilter) inspectPayload(hdr pgwire.Header) ([]byte, error) {
	if hdr.PayloadLen > scratchMax {
		payload, err := pgwire.ReadPayload(f.src, hdr.PayloadLen)
		if err != nil {
			return nil, fmt.Errorf("read client message: %w", err)
		}

		return payload, nil
	}

	if cap(f.scratch) < hdr.PayloadLen {
		f.scratch = make([]byte, hdr.PayloadLen)
	}

	buf := f.scratch[:hdr.PayloadLen]
	if err := f.readInto(buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// readInto fills buf from the client, reporting a stream that dies
// mid-payload as ErrUnexpectedEOF so it cannot pass for a clean close
// on a message boundary.
func (f *msgFilter) readInto(buf []byte) error {
	if _, err := io.ReadFull(f.src, buf); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}

		return fmt.Errorf("read client message payload: %w", err)
	}

	return nil
}

// relay forwards one uninspected message. Ordinary sizes are read into
// the scratch buffer and forwarded in a single write; larger ones are
// streamed so the proxy never materializes them.
func (f *msgFilter) relay(hdr pgwire.Header) error {
	if hdr.PayloadLen > scratchMax {
		return f.stream(hdr)
	}

	payload, err := f.inspectPayload(hdr)
	if err != nil {
		return err
	}

	return f.forwardBuffered(hdr, payload)
}

// stream forwards a message without materializing it: the header, then
// the payload copied straight from the client to the upstream.
func (f *msgFilter) stream(hdr pgwire.Header) error {
	head := hdr.Encode()
	if _, err := f.upstream.Write(head[:]); err != nil {
		return fmt.Errorf("forward client message: %w", err)
	}

	if hdr.PayloadLen > 0 {
		if _, err := io.CopyN(f.upstream, f.src, int64(hdr.PayloadLen)); err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}

			return fmt.Errorf("forward client message: %w", err)
		}
	}

	return nil
}

// forwardBuffered writes an already-read message upstream, header and
// payload in one writev.
func (f *msgFilter) forwardBuffered(hdr pgwire.Header, payload []byte) error {
	if _, err := (pgwire.Message{Type: hdr.Type, Payload: payload}).WriteTo(f.upstream); err != nil {
		return fmt.Errorf("forward client message: %w", err)
	}

	return nil
}

// discardPayload consumes a swallowed message's payload without
// materializing it; io.Discard's ReadFrom keeps it allocation-free.
func (f *msgFilter) discardPayload(hdr pgwire.Header) error {
	if hdr.PayloadLen == 0 {
		return nil
	}

	if _, err := io.CopyN(io.Discard, f.src, int64(hdr.PayloadLen)); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}

		return fmt.Errorf("discard client message: %w", err)
	}

	return nil
}

// holdBudget is how many payload bytes the current batch can still hold,
// leaving room for the five-byte header.
func (f *msgFilter) holdBudget() int {
	return maxHeldBytes - len(f.heldBuf) - 5
}

// hold appends an already-read message to the current batch, copying it
// out of the scratch buffer. One whose payload cannot fit the budget is
// forwarded past the batch instead; the deny path then resyncs through
// the backend rather than synthesizing the whole exchange.
func (f *msgFilter) hold(hdr pgwire.Header, payload []byte) error {
	if hdr.PayloadLen > f.holdBudget() {
		if err := f.flushHeld(); err != nil {
			return err
		}
		f.prefixForwarded = true

		return f.forwardBuffered(hdr, payload)
	}

	head := hdr.Encode()
	f.heldBuf = append(f.heldBuf, head[:]...)
	f.heldBuf = append(f.heldBuf, payload...)

	return nil
}

// holdFromWire reads a message's payload straight into the current
// batch. One that cannot fit the budget is streamed past the batch
// instead, like hold.
func (f *msgFilter) holdFromWire(hdr pgwire.Header) error {
	if hdr.PayloadLen > f.holdBudget() {
		if err := f.flushHeld(); err != nil {
			return err
		}
		f.prefixForwarded = true

		return f.stream(hdr)
	}

	head := hdr.Encode()
	f.heldBuf = append(f.heldBuf, head[:]...)

	start := len(f.heldBuf)
	f.heldBuf = slices.Grow(f.heldBuf, hdr.PayloadLen)[:start+hdr.PayloadLen]

	return f.readInto(f.heldBuf[start:])
}

// flushHeld forwards the held batch upstream in one write and marks the
// batch as partially released, so a later deny in the same batch knows
// the backend saw its prefix. The Sync branch of handle resets that
// mark.
func (f *msgFilter) flushHeld() error {
	if len(f.heldBuf) == 0 {
		return nil
	}

	if _, err := f.upstream.Write(f.heldBuf); err != nil {
		return fmt.Errorf("forward client messages: %w", err)
	}

	f.resetHeld()
	f.prefixForwarded = true

	return nil
}

// resetHeld empties the held batch, keeping the buffer for reuse unless
// it grew unusually large: a session should not pin a budget-sized
// buffer forever on the strength of one batch.
func (f *msgFilter) resetHeld() {
	if cap(f.heldBuf) > scratchMax {
		f.heldBuf = nil

		return
	}

	f.heldBuf = f.heldBuf[:0]
}

// denyBatch refuses the current extended-protocol batch: the held
// messages are discarded, the rest of the batch is swallowed up to its
// Sync, and the client gets an ErrorResponse now. The ReadyForQuery
// that ends the exchange is synthesized at the Sync — unless part of
// the batch already reached the backend, in which case the Sync is
// forwarded and the backend's own ReadyForQuery closes both ends.
func (f *msgFilter) denyBatch(code, msg string) error {
	f.resetHeld()
	f.skipUntilSync = true
	f.forwardSync = f.prefixForwarded

	return f.clientW.writeMessage(pgwire.ErrorResponse(code, msg))
}

// denyQuery answers a blocked simple query the way the backend answers a
// rejected statement: an ErrorResponse followed by ReadyForQuery so the
// client leaves its busy state and can send the next query.
//
// The pair goes out in one write, but it is serialized against backend
// traffic per message: a client that pipelines simple queries without
// waiting for ReadyForQuery can see it land between the messages of an
// earlier query's response stream. Ordering it exactly would take
// ReadyForQuery accounting on the response pump.
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
		if length < 4 || length > maxMessageLen {
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

		// Forward header and payload under one lock so a concurrent deny
		// on the client→upstream pump cannot split this backend message.
		// The upstream read stays inside the lock to keep streaming (no
		// whole-message buffering); a blocked query simply waits until the
		// message is fully forwarded.
		if err := clientW.withLock(func(w io.Writer) error {
			if _, err := w.Write(header[:]); err != nil {
				return fmt.Errorf("forward backend header: %w", err)
			}
			if payloadLen > 0 {
				// io.CopyN lets the client conn's ReadFrom take over, which
				// is splice (zero-copy) between two TCP sockets on Linux —
				// no per-message buffer. io.CopyBuffer would not change this:
				// ReaderFrom takes precedence and the buffer is ignored.
				if _, err := io.CopyN(w, upstream, payloadLen); err != nil {
					return fmt.Errorf("forward backend payload: %w", err)
				}
			}

			return nil
		}); err != nil {
			return err
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

// withLock runs f with the underlying writer while holding the lock, so
// a multi-step write (a message header followed by a streamed payload)
// goes out without another goroutine's write interleaving.
func (w *syncWriter) withLock(f func(io.Writer) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return f(w.w)
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
