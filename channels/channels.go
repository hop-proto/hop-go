package channels

import (
	"bytes"
	"net"
	"sync"
	"time"

	"zmap.io/portal/transport"
)

// TODO(drew): Implement, using the reliable package as a guideline.

// How David would approach this:
//   0. Assume just one channel ID for now
//   1. Implement the message framing (seq no, ack no, all that stuff)
//   2. Implement Read and Write assuming no buffering or out of order or anything like that, using the framing
//   3. Buffering
//   4. Concurrency controls (locks)

// Reliable implements a reliable and ordered channel on top
type Reliable struct {
	m sync.Mutex

	ordered bytes.Buffer
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

func NewReliableChannel(underlying transport.MsgConn) *Reliable {
	panic("implement me")
}

func Dial(protocol, address string) (*Reliable, error) {
	// ignore protocol or check dif udp or check if hop?
	underlying, err := transport.Dial("udp", address, nil)
	if err != nil {
		return nil, err
	}
	return NewReliableChannel(underlying), nil
}

func (r *Reliable) Read(b []byte) (n int, err error) {
	// This part gets hard if you want this call to block until data is available.
	//
	// David recommends not making that work until everything else works.
	return r.ordered.Read(b)
}

func (r *Reliable) Write(b []byte) (n int, err error) {
	// Except with buffering and framing and concurrency control
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
