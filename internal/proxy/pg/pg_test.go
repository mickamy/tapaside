package pg_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mickamy/tapaside/internal/pgwire"
	"github.com/mickamy/tapaside/internal/policy"
	"github.com/mickamy/tapaside/internal/proxy"
	"github.com/mickamy/tapaside/internal/proxy/pg"
)

func listen(t *testing.T) net.Listener {
	t.Helper()

	var lc net.ListenConfig

	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	return l
}

func startProxy(t *testing.T, upstream string, h pg.Handler) string {
	t.Helper()

	l := listen(t)

	srv := proxy.Server{Upstream: upstream, Handler: h}
	go func() { _ = srv.Serve(t.Context(), l) }()

	return l.Addr().String()
}

func dialProxy(t *testing.T, addr string) net.Conn {
	t.Helper()

	var d net.Dialer

	conn, err := d.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	return conn
}

type upstreamResult struct {
	startup pgwire.StartupMessage
	query   pgwire.Message
	err     error
}

func TestHandler_Relay(t *testing.T) {
	t.Parallel()

	upstreamL := listen(t)

	resCh := make(chan upstreamResult, 1)

	go func() {
		conn, err := upstreamL.Accept()
		if err != nil {
			resCh <- upstreamResult{err: fmt.Errorf("accept: %w", err)}

			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		var res upstreamResult

		res.startup, err = pgwire.ReadStartup(conn)
		if err != nil {
			resCh <- upstreamResult{err: fmt.Errorf("read startup: %w", err)}

			return
		}

		authOK := pgwire.Message{Type: 'R', Payload: []byte{0, 0, 0, 0}}
		if _, err := authOK.WriteTo(conn); err != nil {
			resCh <- upstreamResult{err: fmt.Errorf("write auth ok: %w", err)}

			return
		}

		res.query, err = pgwire.ReadMessage(conn)
		if err != nil {
			resCh <- upstreamResult{err: fmt.Errorf("read query: %w", err)}

			return
		}

		ready := pgwire.Message{Type: 'Z', Payload: []byte("I")}
		if _, err := ready.WriteTo(conn); err != nil {
			resCh <- upstreamResult{err: fmt.Errorf("write ready: %w", err)}

			return
		}

		resCh <- res
	}()

	client := dialProxy(t, startProxy(t, upstreamL.Addr().String(), pg.Handler{}))

	// The client side of the sidecar is plaintext: SSLRequest is denied.
	if _, err := (pgwire.StartupMessage{Code: pgwire.SSLRequestCode}).WriteTo(client); err != nil {
		t.Fatalf("write ssl request: %v", err)
	}

	deny := make([]byte, 1)
	if _, err := io.ReadFull(client, deny); err != nil {
		t.Fatalf("read ssl response: %v", err)
	}
	if deny[0] != 'N' {
		t.Fatalf("ssl response = %q, want 'N'", deny[0])
	}

	startupPayload := []byte("user\x00alice\x00\x00")
	if _, err := (pgwire.StartupMessage{Code: 196608, Payload: startupPayload}).WriteTo(client); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	authOK, err := pgwire.ReadMessage(client)
	if err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if authOK.Type != 'R' {
		t.Errorf("auth response type = %c, want R", authOK.Type)
	}

	query := pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1\x00")}
	if _, err := query.WriteTo(client); err != nil {
		t.Fatalf("write query: %v", err)
	}

	ready, err := pgwire.ReadMessage(client)
	if err != nil {
		t.Fatalf("read ready response: %v", err)
	}
	if ready.Type != 'Z' {
		t.Errorf("ready response type = %c, want Z", ready.Type)
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("upstream: %v", res.err)
	}
	if res.startup.Code != 196608 || !bytes.Equal(res.startup.Payload, startupPayload) {
		t.Errorf("upstream startup = %+v, want code 196608 payload %q", res.startup, startupPayload)
	}
	if res.query.Type != query.Type || !bytes.Equal(res.query.Payload, query.Payload) {
		t.Errorf("upstream query = %+v, want %+v", res.query, query)
	}
}

func TestHandler_ReadOnlyBlocksWrite(t *testing.T) {
	t.Parallel()

	upstreamL := listen(t)

	// The upstream records the first message it receives after startup.
	// A blocked write must never reach it, so that message must be the
	// SELECT the client sends afterward.
	firstQuery := make(chan pgwire.Message, 1)
	upErr := make(chan error, 1)

	go func() {
		conn, err := upstreamL.Accept()
		if err != nil {
			upErr <- fmt.Errorf("accept: %w", err)

			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		if _, err := pgwire.ReadStartup(conn); err != nil {
			upErr <- fmt.Errorf("read startup: %w", err)

			return
		}

		m, err := pgwire.ReadMessage(conn)
		if err != nil {
			upErr <- fmt.Errorf("read message: %w", err)

			return
		}

		firstQuery <- m
	}()

	h := pg.Handler{Policy: policy.Policy{ReadOnly: true}}
	client := dialProxy(t, startProxy(t, upstreamL.Addr().String(), h))

	startup := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00alice\x00\x00")}
	if _, err := startup.WriteTo(client); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	// A write: the proxy must block it and answer directly.
	write := pgwire.Message{Type: 'Q', Payload: []byte("DELETE FROM users\x00")}
	if _, err := write.WriteTo(client); err != nil {
		t.Fatalf("write blocked query: %v", err)
	}

	errResp, err := pgwire.ReadMessage(client)
	if err != nil {
		t.Fatalf("read error response: %v", err)
	}
	if errResp.Type != 'E' {
		t.Fatalf("response type = %c, want E (ErrorResponse)", errResp.Type)
	}
	if !bytes.Contains(errResp.Payload, []byte("tapaside policy")) {
		t.Errorf("error payload = %q, want it to mention the policy", errResp.Payload)
	}
	// SQLSTATE 42501 (insufficient_privilege) so clients treat it as a
	// permission error, not a connection fault.
	if !bytes.Contains(errResp.Payload, []byte("C42501")) {
		t.Errorf("error payload = %q, want SQLSTATE 42501", errResp.Payload)
	}

	ready, err := pgwire.ReadMessage(client)
	if err != nil {
		t.Fatalf("read ready for query: %v", err)
	}
	if ready.Type != 'Z' {
		t.Errorf("response type = %c, want Z (ReadyForQuery)", ready.Type)
	}

	// A read after the block still reaches the upstream.
	read := pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1\x00")}
	if _, err := read.WriteTo(client); err != nil {
		t.Fatalf("write allowed query: %v", err)
	}

	select {
	case err := <-upErr:
		t.Fatalf("upstream: %v", err)
	case got := <-firstQuery:
		if !bytes.Equal(got.Payload, read.Payload) {
			t.Errorf("upstream first received %q, want the SELECT %q (the DELETE leaked through)",
				got.Payload, read.Payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream received no message")
	}
}

func TestHandler_ReadOnlyRefusesExtendedProtocol(t *testing.T) {
	t.Parallel()

	upstreamL := listen(t)

	// Records the first message the upstream sees after startup. The
	// refused Parse batch must never reach it, so it must be the SELECT.
	firstQuery := make(chan pgwire.Message, 1)
	upErr := make(chan error, 1)

	go func() {
		conn, err := upstreamL.Accept()
		if err != nil {
			upErr <- fmt.Errorf("accept: %w", err)

			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		if _, err := pgwire.ReadStartup(conn); err != nil {
			upErr <- fmt.Errorf("read startup: %w", err)

			return
		}

		m, err := pgwire.ReadMessage(conn)
		if err != nil {
			upErr <- fmt.Errorf("read message: %w", err)

			return
		}

		firstQuery <- m
	}()

	h := pg.Handler{Policy: policy.Policy{ReadOnly: true}}
	client := dialProxy(t, startProxy(t, upstreamL.Addr().String(), h))

	startup := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00alice\x00\x00")}
	if _, err := startup.WriteTo(client); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	// An extended-protocol batch: Parse a write, then Sync. Under an
	// active policy the proxy must refuse the batch, not forward it.
	parse := pgwire.Message{Type: 'P', Payload: []byte("\x00DELETE FROM users\x00\x00\x00")}
	if _, err := parse.WriteTo(client); err != nil {
		t.Fatalf("write parse: %v", err)
	}

	sync := pgwire.Message{Type: 'S'}
	if _, err := sync.WriteTo(client); err != nil {
		t.Fatalf("write sync: %v", err)
	}

	errResp, err := pgwire.ReadMessage(client)
	if err != nil {
		t.Fatalf("read error response: %v", err)
	}
	if errResp.Type != 'E' {
		t.Fatalf("response type = %c, want E (ErrorResponse)", errResp.Type)
	}
	if !bytes.Contains(errResp.Payload, []byte("extended query protocol")) {
		t.Errorf("error payload = %q, want it to explain the extended protocol is unsupported", errResp.Payload)
	}

	ready, err := pgwire.ReadMessage(client)
	if err != nil {
		t.Fatalf("read ready for query: %v", err)
	}
	if ready.Type != 'Z' {
		t.Errorf("response type = %c, want Z (ReadyForQuery)", ready.Type)
	}

	// The session survives: a simple read afterward reaches the upstream.
	read := pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1\x00")}
	if _, err := read.WriteTo(client); err != nil {
		t.Fatalf("write allowed query: %v", err)
	}

	select {
	case err := <-upErr:
		t.Fatalf("upstream: %v", err)
	case got := <-firstQuery:
		if !bytes.Equal(got.Payload, read.Payload) {
			t.Errorf("upstream first received %q, want the SELECT %q (the Parse leaked through)",
				got.Payload, read.Payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream received no message")
	}
}

func TestHandler_NoPolicyForwardsExtendedProtocol(t *testing.T) {
	t.Parallel()

	upstreamL := listen(t)

	forwarded := make(chan pgwire.Message, 1)
	upErr := make(chan error, 1)

	go func() {
		conn, err := upstreamL.Accept()
		if err != nil {
			upErr <- fmt.Errorf("accept: %w", err)

			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		if _, err := pgwire.ReadStartup(conn); err != nil {
			upErr <- fmt.Errorf("read startup: %w", err)

			return
		}

		m, err := pgwire.ReadMessage(conn)
		if err != nil {
			upErr <- fmt.Errorf("read message: %w", err)

			return
		}

		forwarded <- m
	}()

	// No policy: the proxy is a transparent relay, so extended-protocol
	// messages pass through untouched.
	client := dialProxy(t, startProxy(t, upstreamL.Addr().String(), pg.Handler{}))

	startup := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00alice\x00\x00")}
	if _, err := startup.WriteTo(client); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	parse := pgwire.Message{Type: 'P', Payload: []byte("\x00SELECT 1\x00\x00\x00")}
	if _, err := parse.WriteTo(client); err != nil {
		t.Fatalf("write parse: %v", err)
	}

	select {
	case err := <-upErr:
		t.Fatalf("upstream: %v", err)
	case got := <-forwarded:
		if got.Type != 'P' || !bytes.Equal(got.Payload, parse.Payload) {
			t.Errorf("upstream received %+v, want the Parse forwarded verbatim", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream received no message; the Parse was not forwarded")
	}
}

func TestHandler_CancelRequest(t *testing.T) {
	t.Parallel()

	upstreamL := listen(t)

	resCh := make(chan upstreamResult, 1)

	go func() {
		conn, err := upstreamL.Accept()
		if err != nil {
			resCh <- upstreamResult{err: fmt.Errorf("accept: %w", err)}

			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		startup, err := pgwire.ReadStartup(conn)
		if err != nil {
			resCh <- upstreamResult{err: fmt.Errorf("read startup: %w", err)}

			return
		}

		// The proxy forwards the cancel request and closes without
		// waiting for a response.
		buf := make([]byte, 1)
		if _, err := conn.Read(buf); !errors.Is(err, io.EOF) {
			resCh <- upstreamResult{err: fmt.Errorf("read after cancel = %w, want io.EOF", err)}

			return
		}

		resCh <- upstreamResult{startup: startup}
	}()

	client := dialProxy(t, startProxy(t, upstreamL.Addr().String(), pg.Handler{}))

	cancelPayload := []byte{0, 0, 0, 1, 0, 0, 0, 2} // pid, secret key
	cancel := pgwire.StartupMessage{Code: pgwire.CancelRequestCode, Payload: cancelPayload}
	if _, err := cancel.WriteTo(client); err != nil {
		t.Fatalf("write cancel request: %v", err)
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("upstream: %v", res.err)
	}
	if !res.startup.IsCancelRequest() || !bytes.Equal(res.startup.Payload, cancelPayload) {
		t.Errorf("upstream startup = %+v, want cancel request payload %v", res.startup, cancelPayload)
	}

	buf := make([]byte, 1)
	if _, err := client.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("read after cancel = %v, want io.EOF", err)
	}
}

func TestHandler_StartupTimeout(t *testing.T) {
	t.Parallel()

	// The upstream is never dialed; the client never sends a startup.
	h := pg.Handler{StartupTimeout: 50 * time.Millisecond}
	client := dialProxy(t, startProxy(t, "127.0.0.1:1", h))

	buf := make([]byte, 1)
	if _, err := client.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("read = %v, want io.EOF after the startup timeout", err)
	}
}

func TestHandler_StartupDeadlineCleared(t *testing.T) {
	t.Parallel()

	upstreamL := listen(t)

	go func() {
		conn, err := upstreamL.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		if _, err := pgwire.ReadStartup(conn); err != nil {
			return
		}
		if _, err := pgwire.ReadMessage(conn); err != nil {
			return
		}

		ready := pgwire.Message{Type: 'Z', Payload: []byte("I")}
		_, _ = ready.WriteTo(conn)
	}()

	h := pg.Handler{StartupTimeout: 100 * time.Millisecond}
	client := dialProxy(t, startProxy(t, upstreamL.Addr().String(), h))

	startup := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00alice\x00\x00")}
	if _, err := startup.WriteTo(client); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	// Idle well past the startup timeout: the deadline must have been
	// cleared once startup completed, or this session would be killed.
	time.Sleep(300 * time.Millisecond)

	query := pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1\x00")}
	if _, err := query.WriteTo(client); err != nil {
		t.Fatalf("write query: %v", err)
	}

	ready, err := pgwire.ReadMessage(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if ready.Type != 'Z' {
		t.Errorf("response type = %c, want Z", ready.Type)
	}
}

func TestHandler_StartupTimeoutDisabled(t *testing.T) {
	t.Parallel()

	upstreamL := listen(t)

	go func() {
		conn, err := upstreamL.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		if _, err := pgwire.ReadStartup(conn); err != nil {
			return
		}

		ready := pgwire.Message{Type: 'Z', Payload: []byte("I")}
		_, _ = ready.WriteTo(conn)
	}()

	// A negative timeout must disable the deadline, not arm one that has
	// already expired.
	h := pg.Handler{StartupTimeout: -1}
	client := dialProxy(t, startProxy(t, upstreamL.Addr().String(), h))

	time.Sleep(200 * time.Millisecond)

	startup := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00alice\x00\x00")}
	if _, err := startup.WriteTo(client); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	ready, err := pgwire.ReadMessage(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if ready.Type != 'Z' {
		t.Errorf("response type = %c, want Z", ready.Type)
	}
}

func TestHandler_TooManyEncryptionRequests(t *testing.T) {
	t.Parallel()

	// The upstream is never dialed; any address will do.
	client := dialProxy(t, startProxy(t, "127.0.0.1:1", pg.Handler{}))

	// 3 mirrors maxStartupReads: every read was an encryption request,
	// so the proxy gives up and closes the connection.
	for range 3 {
		if _, err := (pgwire.StartupMessage{Code: pgwire.SSLRequestCode}).WriteTo(client); err != nil {
			t.Fatalf("write ssl request: %v", err)
		}

		deny := make([]byte, 1)
		if _, err := io.ReadFull(client, deny); err != nil {
			t.Fatalf("read ssl response: %v", err)
		}
		if deny[0] != 'N' {
			t.Fatalf("ssl response = %q, want 'N'", deny[0])
		}
	}

	buf := make([]byte, 1)
	if _, err := client.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("read after limit = %v, want io.EOF", err)
	}
}

func TestHandler_ClientHalfClose(t *testing.T) {
	t.Parallel()

	upstreamL := listen(t)

	resCh := make(chan upstreamResult, 1)

	go func() {
		conn, err := upstreamL.Accept()
		if err != nil {
			resCh <- upstreamResult{err: fmt.Errorf("accept: %w", err)}

			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		var res upstreamResult

		res.startup, err = pgwire.ReadStartup(conn)
		if err != nil {
			resCh <- upstreamResult{err: fmt.Errorf("read startup: %w", err)}

			return
		}

		res.query, err = pgwire.ReadMessage(conn)
		if err != nil {
			resCh <- upstreamResult{err: fmt.Errorf("read query: %w", err)}

			return
		}

		// The client half-closed; the proxy must propagate the EOF to us
		// before we reply, proving the response path is still open.
		if _, err := pgwire.ReadMessage(conn); !errors.Is(err, io.EOF) {
			resCh <- upstreamResult{err: fmt.Errorf("read after half-close = %w, want io.EOF", err)}

			return
		}

		ready := pgwire.Message{Type: 'Z', Payload: []byte("I")}
		if _, err := ready.WriteTo(conn); err != nil {
			resCh <- upstreamResult{err: fmt.Errorf("write ready: %w", err)}

			return
		}

		resCh <- res
	}()

	client := dialProxy(t, startProxy(t, upstreamL.Addr().String(), pg.Handler{}))

	startup := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00alice\x00\x00")}
	if _, err := startup.WriteTo(client); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	query := pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1\x00")}
	if _, err := query.WriteTo(client); err != nil {
		t.Fatalf("write query: %v", err)
	}

	tcp, ok := client.(*net.TCPConn)
	if !ok {
		t.Fatalf("client is %T, want *net.TCPConn", client)
	}
	if err := tcp.CloseWrite(); err != nil {
		t.Fatalf("half-close: %v", err)
	}

	// The response written after our half-close must still arrive.
	ready, err := pgwire.ReadMessage(client)
	if err != nil {
		t.Fatalf("read ready response: %v", err)
	}
	if ready.Type != 'Z' {
		t.Errorf("ready response type = %c, want Z", ready.Type)
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("upstream: %v", res.err)
	}
	if res.query.Type != query.Type || !bytes.Equal(res.query.Payload, query.Payload) {
		t.Errorf("upstream query = %+v, want %+v", res.query, query)
	}

	buf := make([]byte, 1)
	if _, err := client.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("read after response = %v, want io.EOF", err)
	}
}

func TestIsDisconnect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "eof", err: io.EOF, want: true},
		{name: "unexpected eof", err: io.ErrUnexpectedEOF, want: true},
		{name: "closed conn", err: net.ErrClosed, want: true},
		{name: "connection reset", err: syscall.ECONNRESET, want: true},
		{name: "broken pipe", err: syscall.EPIPE, want: true},
		{name: "wrapped reset", err: fmt.Errorf("read: %w", syscall.ECONNRESET), want: true},
		{name: "deadline exceeded", err: os.ErrDeadlineExceeded, want: false},
		{name: "arbitrary error", err: errors.New("boom"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := pg.IsDisconnect(tt.err); got != tt.want {
				t.Errorf("IsDisconnect(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// scriptedConn is a net.Conn whose Read serves the given chunks one
// call at a time, then keeps returning finalErr.
type scriptedConn struct {
	chunks   [][]byte
	finalErr error
	call     int
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if c.call < len(c.chunks) {
		n := copy(p, c.chunks[c.call])
		c.call++

		return n, nil
	}

	return 0, c.finalErr
}

func (c *scriptedConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *scriptedConn) Close() error                { return nil }
func (c *scriptedConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *scriptedConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *scriptedConn) SetDeadline(time.Time) error { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *scriptedConn) SetWriteDeadline(time.Time) error {
	return nil
}

// A client that dies abruptly right after a complete message must tear
// the session down immediately — not enter the half-close path and wait
// for a response on behalf of a peer that no longer exists.
func TestHandler_AbruptResetTearsDownSession(t *testing.T) {
	t.Parallel()

	var startup, query bytes.Buffer

	m := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00alice\x00\x00")}
	if _, err := m.WriteTo(&startup); err != nil {
		t.Fatalf("encode startup: %v", err)
	}
	if _, err := (pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1\x00")}).WriteTo(&query); err != nil {
		t.Fatalf("encode query: %v", err)
	}

	client := &scriptedConn{
		chunks:   [][]byte{startup.Bytes(), query.Bytes()},
		finalErr: syscall.ECONNRESET,
	}

	upstreamL := listen(t)

	// The fake upstream consumes the session but never responds and
	// never closes: only a full teardown lets ServeConn return.
	go func() {
		conn, err := upstreamL.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		if _, err := pgwire.ReadStartup(conn); err != nil {
			return
		}
		if _, err := pgwire.ReadMessage(conn); err != nil {
			return
		}

		buf := make([]byte, 1)
		_, _ = conn.Read(buf) // blocks until the proxy closes the conn
	}()

	var d net.Dialer

	dial := func(ctx context.Context) (net.Conn, error) {
		c, err := d.DialContext(ctx, "tcp", upstreamL.Addr().String())
		if err != nil {
			return nil, fmt.Errorf("dial: %w", err)
		}

		return c, nil
	}

	done := make(chan error, 1)
	go func() { done <- (pg.Handler{}).ServeConn(t.Context(), client, dial) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServeConn() = %v, want nil (reset is a clean disconnect)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn did not return; the reset was treated as a half-close")
	}
}

// panicAfterConn is a net.Conn whose Read serves data once, then
// panics, to simulate a bug inside a relay pump.
type panicAfterConn struct {
	data  []byte
	calls int
}

func (c *panicAfterConn) Read(p []byte) (int, error) {
	c.calls++
	if c.calls == 1 {
		return copy(p, c.data), nil
	}

	panic("read exploded")
}

func (c *panicAfterConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *panicAfterConn) Close() error                { return nil }
func (c *panicAfterConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *panicAfterConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *panicAfterConn) SetDeadline(time.Time) error { return nil }
func (c *panicAfterConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *panicAfterConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestHandler_RelayPumpPanicIsContained(t *testing.T) {
	t.Parallel()

	var startup bytes.Buffer

	m := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00alice\x00\x00")}
	if _, err := m.WriteTo(&startup); err != nil {
		t.Fatalf("encode startup: %v", err)
	}

	client := &panicAfterConn{data: startup.Bytes()}

	up, peer := net.Pipe()
	t.Cleanup(func() { _ = up.Close(); _ = peer.Close() })

	// Consume whatever the proxy forwards so pipe writes do not block.
	go func() { _, _ = io.Copy(io.Discard, peer) }()

	dial := func(context.Context) (net.Conn, error) { return up, nil }

	done := make(chan error, 1)
	go func() { done <- (pg.Handler{}).ServeConn(t.Context(), client, dial) }()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "panic") {
			t.Errorf("ServeConn() = %v, want an error mentioning the panic", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn did not return; a relay pump leaked")
	}
}

func TestHandler_UpstreamUnreachable(t *testing.T) {
	t.Parallel()

	// Reserve an address, then close the listener so nothing accepts on it.
	l := listen(t)
	addr := l.Addr().String()
	_ = l.Close()

	client := dialProxy(t, startProxy(t, addr, pg.Handler{}))

	startup := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00alice\x00\x00")}
	if _, err := startup.WriteTo(client); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	buf := make([]byte, 1)
	if _, err := client.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("read after dial failure = %v, want io.EOF", err)
	}
}
