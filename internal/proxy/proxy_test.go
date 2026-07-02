package proxy_test

import (
	"context"
	"fmt"
	"io"
	"net"
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
