package pg_test

import (
	"io"
	"net"
	"slices"
	"testing"

	"github.com/mickamy/tapaside/internal/pgwire"
	"github.com/mickamy/tapaside/internal/policy"
	"github.com/mickamy/tapaside/internal/proxy"
	"github.com/mickamy/tapaside/internal/proxy/pg"
)

// startBenchBackend runs a scripted backend on l: it consumes the
// startup, then answers every fixed-size request with canned bytes, so
// the harness itself allocates nothing per operation.
func startBenchBackend(l net.Listener, reqLen int, response []byte) {
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		if _, err := pgwire.ReadStartup(conn); err != nil {
			return
		}

		buf := make([]byte, reqLen)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			if _, err := conn.Write(response); err != nil {
				return
			}
		}
	}()
}

// benchQueryLoop drives request/response round trips on conn, reading
// each response into a fixed buffer.
func benchQueryLoop(b *testing.B, conn net.Conn, request, response []byte) {
	b.Helper()

	startup := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00bench\x00\x00")}
	if _, err := startup.WriteTo(conn); err != nil {
		b.Fatalf("write startup: %v", err)
	}

	respBuf := make([]byte, len(response))

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := conn.Write(request); err != nil {
			b.Fatalf("write request: %v", err)
		}
		if _, err := io.ReadFull(conn, respBuf); err != nil {
			b.Fatalf("read response: %v", err)
		}
	}
}

// benchmarkProxy measures a query round trip through the proxy with an
// active read-only policy.
func benchmarkProxy(b *testing.B, request, response []byte) {
	b.Helper()

	ctx := b.Context()

	var lc net.ListenConfig

	upstreamL, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen upstream: %v", err)
	}
	defer func() { _ = upstreamL.Close() }()

	startBenchBackend(upstreamL, len(request), response)

	proxyL, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen proxy: %v", err)
	}
	defer func() { _ = proxyL.Close() }()

	srv := proxy.Server{
		Upstream: upstreamL.Addr().String(),
		Handler:  pg.Handler{Policy: policy.Policy{ReadOnly: true}},
	}
	go func() { _ = srv.Serve(ctx, proxyL) }()

	var d net.Dialer

	client, err := d.DialContext(ctx, "tcp", proxyL.Addr().String())
	if err != nil {
		b.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = client.Close() }()

	benchQueryLoop(b, client, request, response)
}

// benchmarkDirect measures the same round trip against the scripted
// backend without the proxy: the baseline its overhead is judged
// against.
func benchmarkDirect(b *testing.B, request, response []byte) {
	b.Helper()

	ctx := b.Context()

	var lc net.ListenConfig

	upstreamL, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen upstream: %v", err)
	}
	defer func() { _ = upstreamL.Close() }()

	startBenchBackend(upstreamL, len(request), response)

	var d net.Dialer

	client, err := d.DialContext(ctx, "tcp", upstreamL.Addr().String())
	if err != nil {
		b.Fatalf("dial upstream: %v", err)
	}
	defer func() { _ = client.Close() }()

	benchQueryLoop(b, client, request, response)
}

func simpleQueryExchange() (request, response []byte) {
	request = (pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1\x00")}).Bytes()

	response = slices.Concat(
		(pgwire.Message{Type: 'C', Payload: []byte("SELECT 1\x00")}).Bytes(),
		pgwire.ReadyForQuery('I').Bytes(),
	)

	return request, response
}

func extendedQueryExchange() (request, response []byte) {
	request = slices.Concat(
		parseMsg("SELECT 1").Bytes(),
		bindUnnamed.Bytes(),
		executeUnnamed.Bytes(),
		syncMsg.Bytes(),
	)

	response = slices.Concat(
		(pgwire.Message{Type: '1'}).Bytes(), // ParseComplete
		(pgwire.Message{Type: '2'}).Bytes(), // BindComplete
		(pgwire.Message{Type: 'C', Payload: []byte("SELECT 1\x00")}).Bytes(),
		pgwire.ReadyForQuery('I').Bytes(),
	)

	return request, response
}

func BenchmarkProxy_SimpleQuery(b *testing.B) {
	request, response := simpleQueryExchange()
	benchmarkProxy(b, request, response)
}

func BenchmarkProxy_ExtendedQuery(b *testing.B) {
	request, response := extendedQueryExchange()
	benchmarkProxy(b, request, response)
}

func BenchmarkDirect_SimpleQuery(b *testing.B) {
	request, response := simpleQueryExchange()
	benchmarkDirect(b, request, response)
}

func BenchmarkDirect_ExtendedQuery(b *testing.B) {
	request, response := extendedQueryExchange()
	benchmarkDirect(b, request, response)
}
