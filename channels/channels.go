package channels

import (
	"crypto/rand"
	"errors"
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

// Reliable implements a reliable and receiveWindow channel on top

const WINDOW_SIZE = 65535

type Reliable struct {
	m             sync.Mutex
	transportConn transport.MsgConn
	receiveWindow []byte
	windowSize    uint16
	ackNo         uint32
	readNo        uint32
	cid           byte
	muxer         *Muxer
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

func NewReliableChannelWithChannelId(underlying transport.MsgConn, muxer *Muxer, windowSize uint16, channelId byte) *Reliable {
	return &Reliable{
		m:             sync.Mutex{},
		transportConn: underlying,
		receiveWindow: make([]byte, WINDOW_SIZE),
		windowSize:    windowSize,
		cid:           channelId,
		readNo:        1,
		muxer:         muxer,
	}
}

func NewReliableChannel(underlying transport.MsgConn, muxer *Muxer, windowSize uint16) (*Reliable, error) {
	cid := []byte{0}
	n, err := rand.Read(cid)
	if err != nil || n != 1 {
		return nil, err
	}
	return &Reliable{
		m:             sync.Mutex{},
		transportConn: underlying,
		receiveWindow: make([]byte, windowSize),
		windowSize:    windowSize,
		cid:           cid[0],
		readNo:        1,
		muxer:         muxer,
	}, nil
}

func (r *Reliable) Initiate() {
	// Set REQ bit to 1.
	meta := byte(1 << 7)

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
		r.windowSize,
		channelType,
		frameNumber,
		data,
	}
	r.muxer.underlying.WriteMsg(p.toBytes())
	// TODO: Wait for Channel initiation response.
}

func (r *Reliable) Receive(pkt *Packet) error {
	// TODO: Handle wraparounds.
	readNo := r.readNo
	windowEnd := r.readNo + uint32(r.windowSize)
	frameNo := pkt.frameNumber

	if (frameNo < readNo || frameNo > windowEnd) ||
		(frameNo+uint32(pkt.dataLength) > windowEnd) ||
		(frameNo+uint32(pkt.dataLength) < readNo) {
		return errors.New("received data has exceeded window length")
	}

	startIdx := frameNo % uint32(r.windowSize)
	endIdx := (frameNo + uint32(pkt.dataLength)) % uint32(r.windowSize)
	copy(r.receiveWindow[startIdx:endIdx], pkt.data)
	if pkt.frameNumber+uint32(pkt.dataLength) >= r.ackNo {
		r.ackNo = pkt.frameNumber + uint32(pkt.dataLength)
	}
	return nil
}

func (r *Reliable) Read(b []byte) (n int, err error) {
	// This part gets hard if you want this call to block until data is available.
	//
	// David recommends not making that work until everything else works.

	var numCopied = 0
	startIdx := r.readNo % uint32(r.windowSize)
	endIdx := r.ackNo % uint32(r.windowSize)
	numCopied += copy(b, r.receiveWindow[startIdx:endIdx])
	r.readNo = (r.readNo + uint32(numCopied)) % uint32(r.windowSize)
	return numCopied, nil
}

func (r *Reliable) Write(b []byte) (n int, err error) {
	// Except with buffering and framing and concurrency control
	pkt := Packet{
		channelID:   r.cid,
		meta:        0,              // TODO
		dataLength:  uint16(len(b)), // TODO: break up b into packet sizes
		windowSize:  r.windowSize,
		channelType: 1, // TODO
		frameNumber: 1, // TODO
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
