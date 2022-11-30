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


// UDPMsgConn is a wrapper around net.UDPConn that implements MsgConn
type UDPMsgConn struct {
	net.UDPConn
}

var _ MsgConn = &UDPMsgConn{}

func MakeUDPMsgConn(underlying *net.UDPConn) *UDPMsgConn {
	return &UDPMsgConn{
		*underlying,
	}
}

func (c *UDPMsgConn) ReadMsg(b []byte) (n int, err error) {
	n, _, _, _, err = c.ReadMsgUDP(b, nil)
	return
}

func (c *UDPMsgConn) WriteMsg(b []byte) (err error) {
	_, _, err = c.WriteMsgUDP(b, nil, nil)
	return
}
