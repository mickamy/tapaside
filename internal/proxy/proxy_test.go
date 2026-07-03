package proxy_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mickamy/tapaside/internal/proxy"
)

type handlerFunc func(ctx context.Context, client net.Conn, dial proxy.Dialer) error

func (f handlerFunc) ServeConn(ctx context.Context, client net.Conn, dial proxy.Dialer) error {
	return f(ctx, client, dial)
}

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

func startProxy(t *testing.T, upstream string, h proxy.Handler) string {
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

type acceptResult struct {
	conn net.Conn
	err  error
}

// stubListener replays scripted Accept results; once the script is
// exhausted it reports net.ErrClosed like a closed listener.
type stubListener struct {
	accepts chan acceptResult
}

func (l *stubListener) Accept() (net.Conn, error) {
	r, ok := <-l.accepts
	if !ok {
		return nil, net.ErrClosed
	}

	return r.conn, r.err
}

func (l *stubListener) Close() error   { return nil }
func (l *stubListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestServer_AcceptRetriesTemporaryErrors(t *testing.T) {
	t.Parallel()

	accepts := make(chan acceptResult, 2)
	accepts <- acceptResult{err: fmt.Errorf("accept: %w", syscall.EMFILE)}
	accepts <- acceptResult{err: fmt.Errorf("accept: %w", syscall.ENFILE)}
	close(accepts)

	noop := handlerFunc(func(context.Context, net.Conn, proxy.Dialer) error { return nil })
	srv := proxy.Server{Upstream: "127.0.0.1:1", Handler: noop}

	if err := srv.Serve(t.Context(), &stubListener{accepts: accepts}); err != nil {
		t.Errorf("Serve() = %v, want nil (temporary errors retried, then clean close)", err)
	}
}

func TestServer_AcceptFatalError(t *testing.T) {
	t.Parallel()

	accepts := make(chan acceptResult, 1)
	accepts <- acceptResult{err: errors.New("boom")}

	noop := handlerFunc(func(context.Context, net.Conn, proxy.Dialer) error { return nil })
	srv := proxy.Server{Upstream: "127.0.0.1:1", Handler: noop}

	err := srv.Serve(t.Context(), &stubListener{accepts: accepts})
	if err == nil || !strings.Contains(err.Error(), "accept") {
		t.Errorf("Serve() = %v, want wrapped accept error", err)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n, _ := b.buf.Write(p) // bytes.Buffer.Write never returns an error

	return n, nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func TestServer_HandlerPanicIsContained(t *testing.T) {
	t.Parallel()

	l := listen(t)

	var log syncBuffer

	h := handlerFunc(func(context.Context, net.Conn, proxy.Dialer) error {
		panic("handler exploded")
	})
	srv := proxy.Server{Upstream: "127.0.0.1:1", Handler: h, Log: &log}
	go func() { _ = srv.Serve(t.Context(), l) }()

	// The second session proves the server survived the first panic.
	for range 2 {
		conn := dialProxy(t, l.Addr().String())

		buf := make([]byte, 1)
		if _, err := conn.Read(buf); !errors.Is(err, io.EOF) {
			t.Fatalf("read = %v, want io.EOF after handler panic", err)
		}
	}

	if !strings.Contains(log.String(), "panic") {
		t.Errorf("log = %q, want it to mention the panic", log.String())
	}
}

func TestServer_NilHandler(t *testing.T) {
	t.Parallel()

	var srv proxy.Server

	if err := srv.Serve(t.Context(), listen(t)); err == nil {
		t.Error("Serve() error = nil, want error")
	}
}

func TestServer_HandlerBridgesConnections(t *testing.T) {
	t.Parallel()

	upstreamL := listen(t)

	// Fake upstream: read one byte, reply with it doubled.
	go func() {
		conn, err := upstreamL.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		buf := make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}

		_, _ = conn.Write([]byte{buf[0], buf[0]})
	}()

	h := handlerFunc(func(ctx context.Context, client net.Conn, dial proxy.Dialer) error {
		upstream, err := dial(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = upstream.Close() }()

		buf := make([]byte, 1)
		if _, err := io.ReadFull(client, buf); err != nil {
			return fmt.Errorf("read client: %w", err)
		}
		if _, err := upstream.Write(buf); err != nil {
			return fmt.Errorf("write upstream: %w", err)
		}

		reply := make([]byte, 2)
		if _, err := io.ReadFull(upstream, reply); err != nil {
			return fmt.Errorf("read upstream: %w", err)
		}
		if _, err := client.Write(reply); err != nil {
			return fmt.Errorf("write client: %w", err)
		}

		return nil
	})

	client := dialProxy(t, startProxy(t, upstreamL.Addr().String(), h))

	if _, err := client.Write([]byte{'x'}); err != nil {
		t.Fatalf("write: %v", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(reply) != "xx" {
		t.Errorf("reply = %q, want %q", reply, "xx")
	}
}

func TestServer_CancelDetachesSessions(t *testing.T) {
	t.Parallel()

	l := listen(t)
	ctx, cancel := context.WithCancel(t.Context())

	started := make(chan struct{})
	canceled := make(chan struct{})
	got := make(chan error, 1)

	h := handlerFunc(func(hctx context.Context, _ net.Conn, _ proxy.Dialer) error {
		close(started)
		<-canceled
		got <- hctx.Err()

		return nil
	})

	srv := proxy.Server{Upstream: "127.0.0.1:1", Handler: h}
	go func() { _ = srv.Serve(ctx, l) }()

	dialProxy(t, l.Addr().String())

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not start")
	}

	cancel()
	close(canceled)

	select {
	case err := <-got:
		if err != nil {
			t.Errorf("session ctx err = %v, want nil after server cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("session did not report")
	}
}

func TestServer_ListenerClose(t *testing.T) {
	t.Parallel()

	l := listen(t)

	noop := handlerFunc(func(context.Context, net.Conn, proxy.Dialer) error { return nil })
	srv := proxy.Server{Upstream: "127.0.0.1:1", Handler: noop}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(t.Context(), l) }()

	_ = l.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve() = %v, want nil after listener close", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve() did not return after listener close")
	}
}

func TestServer_DrainWaitsForSessions(t *testing.T) {
	t.Parallel()

	l := listen(t)
	ctx, cancel := context.WithCancel(t.Context())

	started := make(chan struct{})
	release := make(chan struct{})

	h := handlerFunc(func(context.Context, net.Conn, proxy.Dialer) error {
		close(started)
		<-release

		return nil
	})

	srv := proxy.Server{Upstream: "127.0.0.1:1", Handler: h}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()

	dialProxy(t, l.Addr().String())

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not start")
	}

	cancel()

	select {
	case <-done:
		t.Fatal("Serve() returned before the in-flight session finished")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve() = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve() did not return after the session finished")
	}
}

func TestServer_DrainTimeout(t *testing.T) {
	t.Parallel()

	l := listen(t)
	ctx, cancel := context.WithCancel(t.Context())

	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	h := handlerFunc(func(context.Context, net.Conn, proxy.Dialer) error {
		close(started)
		<-release

		return nil
	})

	var log syncBuffer

	srv := proxy.Server{
		Upstream:     "127.0.0.1:1",
		Handler:      h,
		Log:          &log,
		DrainTimeout: 50 * time.Millisecond,
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()

	dialProxy(t, l.Addr().String())

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not start")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve() = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return after the drain timeout")
	}

	if !strings.Contains(log.String(), "abandoning") {
		t.Errorf("log = %q, want a drain timeout notice", log.String())
	}
}

func TestServer_DrainForceClosesConnections(t *testing.T) {
	t.Parallel()

	l := listen(t)
	ctx, cancel := context.WithCancel(t.Context())

	started := make(chan struct{})

	// The session blocks on conn I/O, not on a channel: only the forced
	// close of its connection can unblock it.
	h := handlerFunc(func(_ context.Context, conn net.Conn, _ proxy.Dialer) error {
		close(started)

		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err != nil {
			return fmt.Errorf("read: %w", err)
		}

		return nil
	})

	var log syncBuffer

	srv := proxy.Server{
		Upstream:     "127.0.0.1:1",
		Handler:      h,
		Log:          &log,
		DrainTimeout: 50 * time.Millisecond,
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()

	dialProxy(t, l.Addr().String())

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not start")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve() = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return; the forced close did not unblock the session")
	}

	if !strings.Contains(log.String(), "closing their connections") {
		t.Errorf("log = %q, want a forced close notice", log.String())
	}
	if strings.Contains(log.String(), "abandoning") {
		t.Errorf("log = %q, want no abandonment after the forced close worked", log.String())
	}
}

func TestServer_MaxConns(t *testing.T) {
	t.Parallel()

	l := listen(t)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	// Accepted sessions greet with 'x' so the test can tell an accepted
	// connection from a rejected one, which sees EOF without a greeting.
	h := handlerFunc(func(_ context.Context, conn net.Conn, _ proxy.Dialer) error {
		if _, err := conn.Write([]byte{'x'}); err != nil {
			return fmt.Errorf("greet: %w", err)
		}
		<-release

		return nil
	})

	var log syncBuffer

	srv := proxy.Server{Upstream: "127.0.0.1:1", Handler: h, Log: &log, MaxConns: 1}
	go func() { _ = srv.Serve(t.Context(), l) }()

	first := dialProxy(t, l.Addr().String())

	buf := make([]byte, 1)
	if _, err := io.ReadFull(first, buf); err != nil || buf[0] != 'x' {
		t.Fatalf("first conn: read = %q, %v; want greeting", buf, err)
	}

	second := dialProxy(t, l.Addr().String())
	if _, err := second.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("second conn: read = %v, want io.EOF (rejected over the limit)", err)
	}
	if !strings.Contains(log.String(), "connection limit") {
		t.Errorf("log = %q, want a connection limit notice", log.String())
	}
}

func TestServer_ContextCancel(t *testing.T) {
	t.Parallel()

	l := listen(t)
	ctx, cancel := context.WithCancel(t.Context())

	noop := handlerFunc(func(context.Context, net.Conn, proxy.Dialer) error { return nil })
	srv := proxy.Server{Upstream: "127.0.0.1:1", Handler: noop}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve() = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve() did not return after cancel")
	}
}
