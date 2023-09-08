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

// UDPMsgConn is an implementations of MsgConn backed by a single UDP socket.
type UDPMsgConn struct {
	net.UDPConn
}

// NewUDPMsgConn allocates a UDPMsgConn wrapping a UDP socket.
func NewUDPMsgConn(underlying *net.UDPConn) *UDPMsgConn {
	return &UDPMsgConn{*underlying}
}

// WriteMsg implement the MsgConn interface
func (c *UDPMsgConn) WriteMsg(b []byte) (err error) {
	_, _, err = c.WriteMsgUDP(b, nil, nil)
	return
}

// ReadMsg implements the MsgConn interface
func (c *UDPMsgConn) ReadMsg(b []byte) (n int, err error) {
	n, _, _, _, err = c.ReadMsgUDP(b, nil)
	return
}

// UDPMsgConn implements MsgConn
var _ MsgConn = &UDPMsgConn{}
