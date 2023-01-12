package transport

import (
	"math/rand"
	"net"
	"time"
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
	odds float64
	net.UDPConn
}

var _ MsgConn = &UDPMsgConn{}

// MakeUDPMsgConn converts a *net.UDPConn into a *UDPMsgConn
func MakeUDPMsgConn(odds float64, underlying *net.UDPConn) *UDPMsgConn {
	rand.Seed(time.Now().UnixNano())
	return &UDPMsgConn{
		odds,
		*underlying,
	}
}

// ReadMsg implements the MsgConn interface
func (c *UDPMsgConn) ReadMsg(b []byte) (n int, err error) {
	n, _, _, _, err = c.ReadMsgUDP(b, nil)
	return
}

// WriteMsg implement the MsgConn interface
func (c *UDPMsgConn) WriteMsg(b []byte) (err error) {
	x := rand.Float64()
	if x < c.odds {
		_, _, err = c.WriteMsgUDP(b, nil, nil)
	}
	return
}
