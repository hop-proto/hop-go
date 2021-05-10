package channels

import (
	"bytes"
	"crypto/rand"
	"net"
	"sync"
	"time"

	"zmap.io/portal/transport"
)

// TODO(drew): Implement, using the reliable package as a guideline.

// How David would approach this:
//   1. Implement the message framing (seq no, ack no, all that stuff)
//   2. Implement Read and Write assuming no buffering or out of order or anything like that, using the framing
//   3. Buffering
//   4. Concurrency controls (locks)

// Reliable implements a reliable and ordered channel on top
type Reliable struct {
	m             sync.Mutex
	transportConn transport.MsgConn
	ordered       bytes.Buffer
	cid           byte
	muxer         *Muxer
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

func NewReliableChannelWithChannelId(underlying transport.MsgConn, muxer *Muxer, channelId byte) *Reliable {
	return &Reliable{sync.Mutex{}, underlying, bytes.Buffer{}, channelId, muxer}
}

func NewReliableChannel(underlying transport.MsgConn, muxer *Muxer) (*Reliable, error) {
	cid := []byte{0}
	n, err := rand.Read(cid)
	if err != nil || n != 1 {
		return nil, err
	}
	return &Reliable{sync.Mutex{}, underlying, bytes.Buffer{}, cid[0], muxer}, nil
}

func (r *Reliable) Initiate() {
	// Set REQ bit to 1.
	meta := byte(1 << 7)

	windowSize := uint16(0)
	// TODO: support various channel types
	channelType := byte(0)
	// Frame Number begins with 0.
	frameNumber := uint32(0)
	data := []byte("Channel initiation request.")
	length := uint16(len(data))
	p := Packet{
		r.cid,
		meta,
		length,
		windowSize,
		channelType,
		frameNumber,
		data,
	}
	r.muxer.underlying.WriteMsg(p.toBytes())
}

func (r *Reliable) Read(b []byte) (n int, err error) {
	// This part gets hard if you want this call to block until data is available.
	//
	// David recommends not making that work until everything else works.
	return r.ordered.Read(b)
}

func (r *Reliable) Write(b []byte) (n int, err error) {
	// Except with buffering and framing and concurrency control
	pkt := Packet{
		channelID:   r.cid,
		meta:        0,              // TODO
		dataLength:  uint16(len(b)), // TODO: break up b into packet sizes
		windowSize:  1000,           // TODO
		channelType: 1,              // TODO
		frameNumber: 1,              // TODO
		data:        b,
	}
	return len(pkt.toBytes()), r.transportConn.WriteMsg(pkt.toBytes())
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
