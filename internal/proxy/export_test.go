package proxy

import (
	"net"
	"time"
)

// NewStallConn exposes stallConn to tests.
func NewStallConn(conn net.Conn, timeout time.Duration) net.Conn {
	return stallConn{Conn: conn, timeout: timeout}
}
