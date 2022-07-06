package transport

import "time"

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
	SetReadDeadline(time.Time) error
}

// Client implements MsgConn
var _ MsgConn = &Client{}
