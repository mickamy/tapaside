package pg_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mickamy/tapaside/internal/pgwire"
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

func startProxy(t *testing.T, upstream string) string {
	t.Helper()

	l := listen(t)

	srv := proxy.Server{Upstream: upstream, Handler: pg.Handler{}}
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

	client := dialProxy(t, startProxy(t, upstreamL.Addr().String()))

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

	client := dialProxy(t, startProxy(t, upstreamL.Addr().String()))

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

func TestHandler_TooManyEncryptionRequests(t *testing.T) {
	t.Parallel()

	// The upstream is never dialed; any address will do.
	client := dialProxy(t, startProxy(t, "127.0.0.1:1"))

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

	client := dialProxy(t, startProxy(t, addr))

	startup := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00alice\x00\x00")}
	if _, err := startup.WriteTo(client); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	buf := make([]byte, 1)
	if _, err := client.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("read after dial failure = %v, want io.EOF", err)
	}
}
