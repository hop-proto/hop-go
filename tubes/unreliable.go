// Unreliable tubes
package tubes

import (
	"net"
	"time"

	"hop.computer/hop/transport"
)

type Unreliable struct {
}

var _ net.Conn = &Unreliable{}
var _ transport.UDPLike = &Unreliable{}

func (u *Unreliable) Read(b []byte) (n int, err error) {
	panic("unimplemented")
}

func (u *Unreliable) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	panic("unimplemented")
}

func (u *Unreliable) Write(b []byte) (n int, err error) {
	panic("unimplemented")
}

func (u *Unreliable) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	panic("unimplemented")
}

func (u *Unreliable) Close() error {
	panic("unimplemented")
}

func (u *Unreliable) LocalAddr() net.Addr {
	panic("unimplemented")
}

func (u *Unreliable) RemoteAddr() net.Addr {
	panic("unimplemented")
}

func (u *Unreliable) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

func (u *Unreliable) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

func (u *Unreliable) SetWriteDeadline(t time.Time) error {
	panic("unimplemented")
}
