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
	m             sync.Mutex
	transportConn transport.MsgConn
	ordered       bytes.Buffer
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

func NewReliableChannel(underlying transport.MsgConn) *Reliable {
	return &Reliable{sync.Mutex{}, underlying, bytes.Buffer{}}
}

func (r *Reliable) Read(b []byte) (n int, err error) {
	// This part gets hard if you want this call to block until data is available.
	//
	// David recommends not making that work until everything else works.
	return r.ordered.Read(b)
}

func (r *Reliable) Write(b []byte) (n int, err error) {
	// Except with buffering and framing and concurrency control
	return r.ordered.Write(b)
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
