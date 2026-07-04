package pgwire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mickamy/tapaside/internal/pgwire"
)

func startupBytes(code uint32, payload []byte) []byte {
	buf := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(buf)))
	binary.BigEndian.PutUint32(buf[4:8], code)
	copy(buf[8:], payload)

	return buf
}

func messageBytes(typ byte, payload []byte) []byte {
	buf := make([]byte, 5+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:5], uint32(4+len(payload)))
	copy(buf[5:], payload)

	return buf
}

func TestReadStartup(t *testing.T) {
	t.Parallel()

	startupPayload := []byte("user\x00alice\x00database\x00app\x00\x00")
	cancelPayload := []byte{0, 0, 0, 1, 0, 0, 0, 2} // pid, secret key

	tests := []struct {
		name    string
		input   []byte
		want    pgwire.StartupMessage
		wantErr string
	}{
		{
			name:  "startup message v3.0",
			input: startupBytes(196608, startupPayload),
			want:  pgwire.StartupMessage{Code: 196608, Payload: startupPayload},
		},
		{
			name:  "ssl request",
			input: startupBytes(pgwire.SSLRequestCode, nil),
			want:  pgwire.StartupMessage{Code: pgwire.SSLRequestCode, Payload: []byte{}},
		},
		{
			name:  "gssenc request",
			input: startupBytes(pgwire.GSSEncRequestCode, nil),
			want:  pgwire.StartupMessage{Code: pgwire.GSSEncRequestCode, Payload: []byte{}},
		},
		{
			name:  "cancel request",
			input: startupBytes(pgwire.CancelRequestCode, cancelPayload),
			want:  pgwire.StartupMessage{Code: pgwire.CancelRequestCode, Payload: cancelPayload},
		},
		{
			name:    "length below minimum",
			input:   []byte{0, 0, 0, 4, 0, 0, 0, 0},
			wantErr: "pgwire: invalid startup packet length",
		},
		{
			name:    "length above maximum",
			input:   []byte{0, 0, 0x27, 0x11, 0, 0, 0, 0}, // 10001
			wantErr: "pgwire: invalid startup packet length",
		},
		{
			name:    "truncated payload",
			input:   startupBytes(196608, startupPayload)[:12],
			wantErr: "pgwire: read startup payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := pgwire.ReadStartup(bytes.NewReader(tt.input))

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ReadStartup() error = %v, want substring %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("ReadStartup() error = %v", err)
			}
			if got.Code != tt.want.Code {
				t.Errorf("Code = %d, want %d", got.Code, tt.want.Code)
			}
			if !bytes.Equal(got.Payload, tt.want.Payload) {
				t.Errorf("Payload = %q, want %q", got.Payload, tt.want.Payload)
			}
		})
	}
}

func TestReadStartup_EOF(t *testing.T) {
	t.Parallel()

	_, err := pgwire.ReadStartup(bytes.NewReader(nil))

	if !errors.Is(err, io.EOF) {
		t.Errorf("ReadStartup() error = %v, want io.EOF", err)
	}
}

func TestStartupMessage_Requests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		code       uint32
		wantSSL    bool
		wantGSS    bool
		wantCancel bool
	}{
		{name: "protocol v3.0", code: 196608},
		{name: "ssl request", code: pgwire.SSLRequestCode, wantSSL: true},
		{name: "gssenc request", code: pgwire.GSSEncRequestCode, wantGSS: true},
		{name: "cancel request", code: pgwire.CancelRequestCode, wantCancel: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := pgwire.StartupMessage{Code: tt.code}

			if got := m.IsSSLRequest(); got != tt.wantSSL {
				t.Errorf("IsSSLRequest() = %v, want %v", got, tt.wantSSL)
			}
			if got := m.IsGSSEncRequest(); got != tt.wantGSS {
				t.Errorf("IsGSSEncRequest() = %v, want %v", got, tt.wantGSS)
			}
			if got := m.IsCancelRequest(); got != tt.wantCancel {
				t.Errorf("IsCancelRequest() = %v, want %v", got, tt.wantCancel)
			}
		})
	}
}

func TestStartupMessage_WriteTo(t *testing.T) {
	t.Parallel()

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()

		m := pgwire.StartupMessage{Code: 196608, Payload: []byte("user\x00alice\x00\x00")}

		var buf bytes.Buffer

		n, err := m.WriteTo(&buf)
		if err != nil {
			t.Fatalf("WriteTo() error = %v", err)
		}
		if n != int64(buf.Len()) {
			t.Errorf("WriteTo() = %d, want %d", n, buf.Len())
		}

		got, err := pgwire.ReadStartup(&buf)
		if err != nil {
			t.Fatalf("ReadStartup() error = %v", err)
		}
		if got.Code != m.Code || !bytes.Equal(got.Payload, m.Payload) {
			t.Errorf("round trip = %+v, want %+v", got, m)
		}
	})

	t.Run("payload too large", func(t *testing.T) {
		t.Parallel()

		m := pgwire.StartupMessage{Code: 196608, Payload: make([]byte, 10000)}

		if _, err := m.WriteTo(io.Discard); err == nil {
			t.Error("WriteTo() error = nil, want error")
		}
	})
}

func TestReadMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		want    pgwire.Message
		wantErr string
	}{
		{
			name:  "simple query",
			input: messageBytes('Q', []byte("SELECT 1\x00")),
			want:  pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1\x00")},
		},
		{
			name:  "empty payload",
			input: messageBytes('S', nil),
			want:  pgwire.Message{Type: 'S', Payload: []byte{}},
		},
		{
			name:    "length below minimum",
			input:   []byte{'Q', 0, 0, 0, 3},
			wantErr: "pgwire: invalid message length",
		},
		{
			name:    "length above maximum",
			input:   []byte{'Q', 0x40, 0, 0, 1}, // 1<<30 + 1
			wantErr: "pgwire: invalid message length",
		},
		{
			name:    "truncated payload",
			input:   messageBytes('Q', []byte("SELECT 1\x00"))[:8],
			wantErr: "pgwire: read message payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := pgwire.ReadMessage(bytes.NewReader(tt.input))

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ReadMessage() error = %v, want substring %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("ReadMessage() error = %v", err)
			}
			if got.Type != tt.want.Type {
				t.Errorf("Type = %c, want %c", got.Type, tt.want.Type)
			}
			if !bytes.Equal(got.Payload, tt.want.Payload) {
				t.Errorf("Payload = %q, want %q", got.Payload, tt.want.Payload)
			}
		})
	}
}

func TestReadMessage_LargePayload(t *testing.T) {
	t.Parallel()

	// Larger than the 64 KiB read chunk so the payload spans several reads.
	payload := bytes.Repeat([]byte{0xAB}, 200<<10)

	got, err := pgwire.ReadMessage(bytes.NewReader(messageBytes('d', payload)))
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if got.Type != 'd' || !bytes.Equal(got.Payload, payload) {
		t.Errorf("ReadMessage() = type %c payload %d bytes, want type d payload %d bytes",
			got.Type, len(got.Payload), len(payload))
	}
}

func TestReadMessage_TruncatedAtChunkBoundary(t *testing.T) {
	t.Parallel()

	// The stream ends exactly at a 64 KiB chunk boundary; this must not
	// look like a clean close between messages.
	full := messageBytes('Q', make([]byte, 128<<10))
	input := full[:5+(64<<10)]

	_, err := pgwire.ReadMessage(bytes.NewReader(input))

	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("ReadMessage() error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadMessage_EOF(t *testing.T) {
	t.Parallel()

	_, err := pgwire.ReadMessage(bytes.NewReader(nil))

	if !errors.Is(err, io.EOF) {
		t.Errorf("ReadMessage() error = %v, want io.EOF", err)
	}
}

func TestReadHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		want    pgwire.Header
		wantErr string
	}{
		{
			name:  "query header",
			input: messageBytes('Q', []byte("SELECT 1\x00")),
			want:  pgwire.Header{Type: 'Q', PayloadLen: 9},
		},
		{
			name:  "empty payload",
			input: messageBytes('S', nil),
			want:  pgwire.Header{Type: 'S', PayloadLen: 0},
		},
		{
			name:    "length below minimum",
			input:   []byte{'Q', 0, 0, 0, 3},
			wantErr: "pgwire: invalid message length",
		},
		{
			name:    "length above maximum",
			input:   []byte{'Q', 0x40, 0, 0, 1}, // 1<<30 + 1
			wantErr: "pgwire: invalid message length",
		},
		{
			name:    "truncated header",
			input:   []byte{'Q', 0, 0},
			wantErr: "pgwire: read message header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := pgwire.ReadHeader(bytes.NewReader(tt.input))

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ReadHeader() error = %v, want substring %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("ReadHeader() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ReadHeader() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestHeader_Encode(t *testing.T) {
	t.Parallel()

	// Encode must reproduce the exact frame ReadHeader consumed.
	wire := messageBytes('d', []byte("copy data"))

	hdr, err := pgwire.ReadHeader(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("ReadHeader() error = %v", err)
	}

	if got := hdr.Encode(); !bytes.Equal(got[:], wire[:5]) {
		t.Errorf("Encode() = %v, want %v", got, wire[:5])
	}
}

func TestMessage_QueryText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		m    pgwire.Message
		want string
	}{
		{
			name: "query with terminator",
			m:    pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1\x00")},
			want: "SELECT 1",
		},
		{
			name: "query without terminator",
			m:    pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1")},
			want: "SELECT 1",
		},
		{
			name: "empty payload",
			m:    pgwire.Message{Type: 'Q', Payload: nil},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.m.QueryText(); got != tt.want {
				t.Errorf("QueryText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMessage_IsQuery(t *testing.T) {
	t.Parallel()

	if !(pgwire.Message{Type: 'Q'}).IsQuery() {
		t.Error("IsQuery() = false for 'Q', want true")
	}
	if (pgwire.Message{Type: 'P'}).IsQuery() {
		t.Error("IsQuery() = true for 'P', want false")
	}
}

func TestMessage_IsParse(t *testing.T) {
	t.Parallel()

	if !(pgwire.Message{Type: 'P'}).IsParse() {
		t.Error("IsParse() = false for 'P', want true")
	}
	if (pgwire.Message{Type: 'Q'}).IsParse() {
		t.Error("IsParse() = true for 'Q', want false")
	}
}

// parsePayload builds a Parse message payload: statement name, query
// (both null-terminated), then a parameter-type count and OIDs.
func parsePayload(name, query string, paramOIDs ...uint32) []byte {
	var b bytes.Buffer

	b.WriteString(name)
	b.WriteByte(0)
	b.WriteString(query)
	b.WriteByte(0)

	var count [2]byte
	binary.BigEndian.PutUint16(count[:], uint16(len(paramOIDs)))
	b.Write(count[:])

	for _, oid := range paramOIDs {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], oid)
		b.Write(buf[:])
	}

	return b.Bytes()
}

func TestMessage_ParseQueryText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		want    string
		wantErr string
	}{
		{
			name:    "named statement",
			payload: parsePayload("stmt_1", "SELECT id FROM users WHERE id = $1"),
			want:    "SELECT id FROM users WHERE id = $1",
		},
		{
			name:    "unnamed statement",
			payload: parsePayload("", "SELECT 1"),
			want:    "SELECT 1",
		},
		{
			name:    "with parameter type oids",
			payload: parsePayload("stmt_1", "SELECT $1::int", 23),
			want:    "SELECT $1::int",
		},
		{
			name:    "empty query",
			payload: parsePayload("", ""),
			want:    "",
		},
		{
			name:    "missing parameter count tail",
			payload: []byte("stmt_1\x00SELECT 1\x00"),
			want:    "SELECT 1",
		},
		{
			name:    "unterminated statement name",
			payload: []byte("stmt_1"),
			wantErr: "unterminated statement name",
		},
		{
			name:    "unterminated query",
			payload: []byte("stmt_1\x00SELECT 1"),
			wantErr: "unterminated query",
		},
		{
			name:    "empty payload",
			payload: nil,
			wantErr: "unterminated statement name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := pgwire.Message{Type: 'P', Payload: tt.payload}

			got, err := m.ParseQueryText()

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseQueryText() error = %v, want substring %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("ParseQueryText() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("ParseQueryText() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrorResponse(t *testing.T) {
	t.Parallel()

	m := pgwire.ErrorResponse("42501", "blocked by tapaside policy")

	if m.Type != 'E' {
		t.Errorf("Type = %c, want E", m.Type)
	}

	want := "S" + "ERROR" + "\x00" +
		"V" + "ERROR" + "\x00" +
		"C" + "42501" + "\x00" +
		"M" + "blocked by tapaside policy" + "\x00" +
		"\x00"
	if got := string(m.Payload); got != want {
		t.Errorf("Payload = %q, want %q", got, want)
	}
}

func TestReadyForQuery(t *testing.T) {
	t.Parallel()

	m := pgwire.ReadyForQuery('I')

	if m.Type != 'Z' {
		t.Errorf("Type = %c, want Z", m.Type)
	}
	if !bytes.Equal(m.Payload, []byte{'I'}) {
		t.Errorf("Payload = %v, want ['I']", m.Payload)
	}
}

func TestMessage_Bytes(t *testing.T) {
	t.Parallel()

	m := pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1\x00")}

	got := m.Bytes()

	// Bytes must equal what WriteTo produces, but in a single slice.
	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if !bytes.Equal(got, buf.Bytes()) {
		t.Errorf("Bytes() = %q, want %q", got, buf.Bytes())
	}

	// And it must round-trip back through ReadMessage.
	rt, err := pgwire.ReadMessage(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if rt.Type != m.Type || !bytes.Equal(rt.Payload, m.Payload) {
		t.Errorf("round trip = %+v, want %+v", rt, m)
	}
}

func TestMessage_WriteTo(t *testing.T) {
	t.Parallel()

	m := pgwire.Message{Type: 'Q', Payload: []byte("SELECT 1\x00")}

	var buf bytes.Buffer

	n, err := m.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if n != int64(buf.Len()) {
		t.Errorf("WriteTo() = %d, want %d", n, buf.Len())
	}

	got, err := pgwire.ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if got.Type != m.Type || !bytes.Equal(got.Payload, m.Payload) {
		t.Errorf("round trip = %+v, want %+v", got, m)
	}
}
