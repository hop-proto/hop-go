package transport

import (
	"net"
)

// MsgReader captures the read method for a message-oriented connection.
type MsgReader interface {
	ReadMsg(b []byte) (int, error)
}

// MsgWriter captures the write method for a message-oriented connection.
type MsgWriter interface {
	WriteMsg(b []byte) error
}

// MsgConn models message-oriented connections.
type MsgConn interface {
	MsgReader
	MsgWriter
	net.Conn
}

// Client implements MsgConn
var _ MsgConn = &Client{}

// Handle implements MsgConn
var _ MsgConn = &Handle{}
