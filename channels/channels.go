package channels

import (
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/transport"
)

// TODO(drew): Implement, using the reliable package as a guideline.

// How David would approach this:
//   1. Implement the message framing (seq no, ack no, all that stuff)
//   2. Implement Read and Write assuming no buffering or out of order or anything like that, using the framing
//   3. Buffering
//   4. Concurrency controls (locks)

// Reliable implements a reliable and receiveWindow channel on top
const SEND_BUFFER_SIZE = 8092

type Reliable struct {
	m              sync.Mutex
	transportConn  transport.MsgConn
	sendBuffer     []byte
	sendSeqNo      uint32
	recvWindow     []byte
	recvWindowSize uint16
	recvAckNo      uint32
	recvReadNo     uint32
	cid            byte
	muxer          *Muxer
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

func NewReliableChannelWithChannelId(underlying transport.MsgConn, muxer *Muxer, windowSize uint16, channelId byte) *Reliable {
	return &Reliable{
		m:              sync.Mutex{},
		transportConn:  underlying,
		recvWindow:     make([]byte, windowSize),
		recvWindowSize: windowSize,
		cid:            channelId,
		recvReadNo:     1,
		recvAckNo:      1,
		sendBuffer:     make([]byte, 0),
		muxer:          muxer,
	}
}

func NewReliableChannel(underlying transport.MsgConn, muxer *Muxer, windowSize uint16) (*Reliable, error) {
	cid := []byte{0}
	n, err := rand.Read(cid)
	if err != nil || n != 1 {
		return nil, err
	}
	return &Reliable{
		m:              sync.Mutex{},
		transportConn:  underlying,
		recvWindow:     make([]byte, windowSize),
		recvWindowSize: windowSize,
		cid:            cid[0],
		recvReadNo:     1,
		sendSeqNo:      1,
		muxer:          muxer,
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
	p := InitiatePacket{
		r.cid,
		meta,
		length,
		r.recvWindowSize,
		channelType,
		frameNumber,
		data,
	}
	r.muxer.underlying.WriteMsg(p.toBytes())
	// TODO: Wait for Channel initiation response.
}

func (r *Reliable) Receive(pkt *Packet) error {
	r.sendBuffer = r.sendBuffer[pkt.ackNo-r.sendSeqNo:]
	r.sendSeqNo = pkt.ackNo
	// TODO: Handle wraparounds.
	readNo := r.recvReadNo
	windowEnd := r.recvReadNo + uint32(r.recvWindowSize)
	frameNo := pkt.frameNo
	logrus.Info("READ NO ", readNo, " FRAME ", frameNo, "window end ", windowEnd, "ACK NO", r.recvAckNo)
	if (frameNo < readNo || frameNo > windowEnd) ||
		(frameNo+uint32(pkt.dataLength) > windowEnd) ||
		(frameNo+uint32(pkt.dataLength) < readNo) {
		return errors.New("received data has exceeded window length")
	}
	startIdx := frameNo % uint32(r.recvWindowSize)
	endIdx := (frameNo + uint32(pkt.dataLength)) % uint32(r.recvWindowSize)
	logrus.Info("READ NO ", readNo, " FRAME ", frameNo, " start idx ", startIdx, " end idx NO ", endIdx)
	copy(r.recvWindow[startIdx:endIdx], pkt.data)
	if pkt.frameNo+uint32(pkt.dataLength) >= r.recvAckNo {
		r.recvAckNo = pkt.frameNo + uint32(pkt.dataLength)
	}
	return nil
}

func (r *Reliable) Read(b []byte) (n int, err error) {
	// This part gets hard if you want this call to block until data is available.
	//
	// David recommends not making that work until everything else works.

	var numCopied = 0
	startIdx := r.recvReadNo % uint32(r.recvWindowSize)

	logrus.Info("RECV NO ", r.recvReadNo, r.recvAckNo, r.recvWindowSize)
	endIdx := r.recvAckNo % uint32(r.recvWindowSize)
	numCopied += copy(b, r.recvWindow[startIdx:endIdx])
	r.recvReadNo = (r.recvReadNo + uint32(numCopied)) % uint32(r.recvWindowSize)
	return numCopied, nil
}

func (r *Reliable) Write(b []byte) (n int, err error) {
	r.sendBuffer = append(r.sendBuffer, b...)
	// Except with buffering and framing and concurrency control
	pkt := Packet{
		channelID:  r.cid,
		meta:       0,                         // TODO
		dataLength: uint16(len(r.sendBuffer)), // TODO: break up b into packet sizes
		ackNo:      r.recvAckNo,
		frameNo:    r.sendSeqNo, // TODO
		data:       r.sendBuffer,
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
