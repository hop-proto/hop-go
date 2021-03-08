package channels

import (
	"net"
	"time"
)

// TODO(drew): Implement, using the reliable package as a guideline.

// Reliable implements a reliable and ordered channel on top
type Reliable struct {
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}


func (r *Reliable) Read(b []byte) (n int, err error) {
	panic("implement me")
}

func (r *Reliable) Write(b []byte) (n int, err error) {
	panic("implement me")
}

func (r *Reliable) Close() error {
	panic("implement me")
}

func (r *Reliable) LocalAddr() net.Addr {
	panic("implement me")
}

func (r *Reliable) RemoteAddr() net.Addr {
	panic("implement me")
}

func (r *Reliable) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (r *Reliable) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (r *Reliable) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

