// Package pgwire implements minimal framing for the PostgreSQL
// frontend/backend protocol (version 3.0).
package pgwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Special request codes sent in place of a protocol version during the
// startup phase.
const (
	CancelRequestCode = 80877102
	SSLRequestCode    = 80877103
	GSSEncRequestCode = 80877104
)

const (
	// maxStartupLength mirrors PostgreSQL's MAX_STARTUP_PACKET_LENGTH.
	maxStartupLength = 10000
	// maxMessageLength mirrors PostgreSQL's 1 GB message size limit.
	maxMessageLength = 1 << 30
)

var (
	_ io.WriterTo = (*StartupMessage)(nil)
	_ io.WriterTo = (*Message)(nil)
)

// StartupMessage is an untyped message sent by the client before the
// session is established: int32 length (self-inclusive), int32 request
// code (protocol version or one of the special request codes), payload.
type StartupMessage struct {
	Code    uint32
	Payload []byte
}

// ReadStartup reads one startup-phase message from r.
func ReadStartup(r io.Reader) (StartupMessage, error) {
	var head [8]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return StartupMessage{}, fmt.Errorf("pgwire: read startup header: %w", err)
	}

	length := binary.BigEndian.Uint32(head[:4])
	if length < 8 || length > maxStartupLength {
		return StartupMessage{}, fmt.Errorf("pgwire: invalid startup packet length %d", length)
	}

	payload := make([]byte, length-8)
	if _, err := io.ReadFull(r, payload); err != nil {
		return StartupMessage{}, fmt.Errorf("pgwire: read startup payload: %w", err)
	}

	return StartupMessage{Code: binary.BigEndian.Uint32(head[4:8]), Payload: payload}, nil
}

func (m StartupMessage) IsCancelRequest() bool { return m.Code == CancelRequestCode }

func (m StartupMessage) IsSSLRequest() bool { return m.Code == SSLRequestCode }

func (m StartupMessage) IsGSSEncRequest() bool { return m.Code == GSSEncRequestCode }

// WriteTo writes the message in wire format. On a net.Conn the header
// and payload go out in one writev call, without copying the payload
// into a contiguous buffer.
func (m StartupMessage) WriteTo(w io.Writer) (int64, error) {
	length := 8 + len(m.Payload)
	if length > maxStartupLength {
		return 0, fmt.Errorf("pgwire: startup payload too large: %d bytes", len(m.Payload))
	}

	var head [8]byte
	binary.BigEndian.PutUint32(head[:4], uint32(length))
	binary.BigEndian.PutUint32(head[4:8], m.Code)

	bufs := net.Buffers{head[:], m.Payload}

	n, err := bufs.WriteTo(w)
	if err != nil {
		return n, fmt.Errorf("pgwire: write startup message: %w", err)
	}

	return n, nil
}

// Message is a typed message exchanged after startup: 1 type byte,
// int32 length (self-inclusive, excluding the type byte), payload.
type Message struct {
	Type    byte
	Payload []byte
}

// IsQuery reports whether m is a simple Query message ('Q').
func (m Message) IsQuery() bool { return m.Type == 'Q' }

// IsParse reports whether m is an extended-protocol Parse message ('P').
func (m Message) IsParse() bool { return m.Type == 'P' }

// QueryText returns the SQL of a simple Query message: the payload up
// to its null terminator. It is meaningful only when IsQuery reports
// true.
func (m Message) QueryText() string {
	s := m.Payload
	if i := bytes.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}

	return string(s)
}

// ParseQueryText returns the SQL carried by a Parse message: the query
// string that follows the statement name in its payload. It is
// meaningful only when IsParse reports true. A payload missing either
// null terminator is reported as an error so a caller enforcing a
// policy can refuse the message instead of evaluating a guess.
func (m Message) ParseQueryText() (string, error) {
	_, rest, ok := bytes.Cut(m.Payload, []byte{0})
	if !ok {
		return "", errors.New("pgwire: parse message: unterminated statement name")
	}

	query, _, ok := bytes.Cut(rest, []byte{0})
	if !ok {
		return "", errors.New("pgwire: parse message: unterminated query")
	}

	return string(query), nil
}

// ErrorResponse builds an ErrorResponse message ('E') with severity
// ERROR, the given SQLSTATE code, and a human-readable message.
func ErrorResponse(code, message string) Message {
	return errorResponse("ERROR", code, message)
}

// FatalResponse builds an ErrorResponse message ('E') with severity
// FATAL, the severity a backend uses for errors that end the session
// during startup.
func FatalResponse(code, message string) Message {
	return errorResponse("FATAL", code, message)
}

func errorResponse(severity, code, message string) Message {
	var b bytes.Buffer

	field := func(typ byte, val string) {
		b.WriteByte(typ)
		b.WriteString(val)
		b.WriteByte(0)
	}

	field('S', severity)
	field('V', severity)
	field('C', code)
	field('M', message)
	b.WriteByte(0)

	return Message{Type: 'E', Payload: b.Bytes()}
}

// ReadyForQuery builds a ReadyForQuery message ('Z') with the given
// transaction status: 'I' idle, 'T' in a transaction, 'E' in a failed
// transaction.
func ReadyForQuery(status byte) Message {
	return Message{Type: 'Z', Payload: []byte{status}}
}

// Header is the frame of a typed message, read ahead of its payload so
// a relay can decide whether to buffer, hold, or stream the rest.
type Header struct {
	Type byte
	// PayloadLen is the payload size in bytes: the wire-format length
	// minus its own four bytes.
	PayloadLen int
}

// ReadHeader reads and validates the five-byte frame of a typed
// message from r, leaving the payload unread.
func ReadHeader(r io.Reader) (Header, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Header{}, fmt.Errorf("pgwire: read message header: %w", err)
	}

	length := binary.BigEndian.Uint32(head[1:5])
	if length < 4 || length > maxMessageLength {
		return Header{}, fmt.Errorf("pgwire: invalid message length %d", length)
	}

	return Header{Type: head[0], PayloadLen: int(length - 4)}, nil
}

// Encode returns the header in wire format. It panics on a payload
// length outside the protocol limit, which a header read from the wire
// never carries.
func (h Header) Encode() [5]byte {
	if h.PayloadLen < 0 || h.PayloadLen > maxMessageLength-4 {
		panic(fmt.Sprintf("pgwire: invalid payload length %d", h.PayloadLen))
	}

	var head [5]byte

	head[0] = h.Type
	binary.BigEndian.PutUint32(head[1:5], uint32(h.PayloadLen+4))

	return head
}

// ReadMessage reads one typed message from r.
func ReadMessage(r io.Reader) (Message, error) {
	hdr, err := ReadHeader(r)
	if err != nil {
		return Message{}, err
	}

	payload, err := ReadPayload(r, hdr.PayloadLen)
	if err != nil {
		return Message{}, err
	}

	return Message{Type: hdr.Type, Payload: payload}, nil
}

// ReadPayload reads size bytes from r, growing the buffer as bytes
// arrive instead of trusting size up front, so a peer cannot force a
// large allocation with a small header alone. The buffer doubles on
// each growth (append-style ~1.25x growth for large slices would copy
// ~4.5x the payload in total; doubling keeps it at ~1x). A stream that
// ends mid-payload reports io.ErrUnexpectedEOF, even at a chunk
// boundary.
func ReadPayload(r io.Reader, size int) ([]byte, error) {
	const chunk = 64 << 10

	payload := make([]byte, 0, min(size, chunk))

	for len(payload) < size {
		if len(payload) == cap(payload) {
			grown := make([]byte, len(payload), min(2*cap(payload), size))
			copy(grown, payload)
			payload = grown
		}

		start := len(payload)
		payload = payload[:cap(payload)]

		if _, err := io.ReadFull(r, payload[start:]); err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}

			return nil, fmt.Errorf("pgwire: read message payload: %w", err)
		}
	}

	return payload, nil
}

// WriteTo writes the message in wire format. On a net.Conn the header
// and payload go out in one writev call, without copying the payload
// into a contiguous buffer.
//
// Note that on a plain io.Writer, net.Buffers falls back to one Write
// per buffer (header, then payload). A caller that shares the writer
// with another goroutine and needs the message to be indivisible must
// use Bytes and a single Write instead.
func (m Message) WriteTo(w io.Writer) (int64, error) {
	length := 4 + len(m.Payload)
	if length > maxMessageLength {
		return 0, fmt.Errorf("pgwire: message payload too large: %d bytes", len(m.Payload))
	}

	head := [5]byte{m.Type}
	binary.BigEndian.PutUint32(head[1:5], uint32(length))

	bufs := net.Buffers{head[:], m.Payload}

	n, err := bufs.WriteTo(w)
	if err != nil {
		return n, fmt.Errorf("pgwire: write message: %w", err)
	}

	return n, nil
}

// Bytes returns the message in wire format as a single contiguous slice,
// for callers that must write it in one Write call. It panics if the
// payload exceeds the protocol limit, which a well-formed message never
// does.
func (m Message) Bytes() []byte {
	length := 4 + len(m.Payload)
	if length > maxMessageLength {
		panic(fmt.Sprintf("pgwire: message payload too large: %d bytes", len(m.Payload)))
	}

	buf := make([]byte, 5+len(m.Payload))
	buf[0] = m.Type
	binary.BigEndian.PutUint32(buf[1:5], uint32(length))
	copy(buf[5:], m.Payload)

	return buf
}
