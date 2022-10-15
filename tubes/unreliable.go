// Package tubes implements the multiplexing of raw data into logical channels of a hop session
package tubes

import (
	"net"
	"time"

	"hop.computer/hop/transport"
)

// Unreliable implements UDP-like messages for Hop
type Unreliable struct {
}

// Unreliable tubes implement net.Conn
var _ net.Conn = &Unreliable{}

// Unreliable tubes work as a drop in replacement for UDP
var _ transport.UDPLike = &Unreliable{}

// Unreliable tubes are tubes
var _ Tube = &Unreliable{}

func newUnreliableTube(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tubeType TubeType) (*Unreliable, error) {
	panic("unimplemented")
}

func (u *Unreliable) receiveInitiatePkt(pkt *initiateFrame) error {
	panic("unimplemented")
}

func (u *Unreliable) receive(pkt *frame) error {
	panic("unimplemented")
}

// Read implements net.Conn. It wraps ReadMsgUDP
func (u *Unreliable) Read(b []byte) (n int, err error) {
	panic("unimplemented")
}

// ReadMsgUDP implements the UDPLike interface
func (u *Unreliable) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	panic("unimplemented")
}

// Write implements net.Conn. It wraps WriteMsgUDP
func (u *Unreliable) Write(b []byte) (n int, err error) {
	panic("unimplemented")
}

// WriteMsgUDP implements implements the UDPLike interface
func (u *Unreliable) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	panic("unimplemented")
}

// Close implements the net.Conn interface. Future io operations will return io.EOF
func (u *Unreliable) Close() error {
	panic("unimplemented")
}

// LocalAddr implements net.Conn
func (u *Unreliable) LocalAddr() net.Addr {
	panic("unimplemented")
}

// RemoteAddr implements net.Conn
func (u *Unreliable) RemoteAddr() net.Addr {
	panic("unimplemented")
}

// SetDeadline implements net.Conn
func (u *Unreliable) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetReadDeadline implements net.Conn
func (u *Unreliable) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetWriteDeadline implements net.Conn
func (u *Unreliable) SetWriteDeadline(t time.Time) error {
	panic("unimplemented")
}

// Type returns the tube type
func (u *Unreliable) Type() TubeType {
	panic("unimplemented")
}

// GetID returns the ID number of the tube
func (u *Unreliable) GetID() byte {
	panic("unimplemented")
}

// IsReliable returns whether the tube is reliable. Always false
func (u *Unreliable) IsReliable() bool {
	return false
}
