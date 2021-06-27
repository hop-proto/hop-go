package channels

import (
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

// Reliable implements a reliable and receiveWindow channel on top
const SEND_BUFFER_SIZE = 8092

type Reliable struct {
	cid        byte
	closed     bool
	m          sync.Mutex
	sendQueue  chan []byte
	recvWindow ReceiveWindow
	sender     Sender
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

func (r *Reliable) send() {
	for {
		pkt := <-r.sender.sendQueue
		pkt.channelID = r.cid
		pkt.ackNo = uint32(r.recvWindow.ackNo)
		// logrus.Info("sending ", pkt.data, " ackno: ", pkt.ackNo, " seq no: ", pkt.frameNo)
		r.sendQueue <- pkt.toBytes()
	}
}

func NewReliableChannelWithChannelId(underlying transport.MsgConn, sendQueue chan []byte, windowSize uint16, channelId byte) *Reliable {
	r := &Reliable{
		cid: channelId,
		m:   sync.Mutex{},
		recvWindow: ReceiveWindow{
			fragments:   make(PriorityQueue, 0),
			maxSize:     windowSize,
			windowStart: 0,
		},
		sender: Sender{
			ackNo:      0,
			buffer:     make([]byte, 0),
			RTO:        time.Millisecond * 50,
			sendQueue:  make(chan *Packet),
			windowSize: 1,
		},
		sendQueue: sendQueue,
	}
	r.recvWindow.init()
	go r.sender.retransmit()
	go r.send()
	return r
}

func NewReliableChannel(underlying transport.MsgConn, sendQueue chan []byte, windowSize uint16) (*Reliable, error) {
	cid := []byte{0}
	n, err := rand.Read(cid)
	if err != nil || n != 1 {
		return nil, err
	}
	r := &Reliable{
		cid: cid[0],
		m:   sync.Mutex{},
		recvWindow: ReceiveWindow{
			fragments:   make(PriorityQueue, 0),
			maxSize:     windowSize,
			windowStart: 0,
		},
		sender: Sender{
			ackNo:      0,
			buffer:     make([]byte, 0),
			windowSize: 1,
			RTO:        time.Millisecond * 50,
			sendQueue:  make(chan *Packet),
		},
		sendQueue: sendQueue,
	}
	r.recvWindow.init()
	go r.sender.retransmit()
	go r.send()
	return r, nil
}

func (r *Reliable) Initiate() {

	channelType := byte(0)

	p := InitiatePacket{
		channelID:   r.cid,
		channelType: channelType,
		data:        []byte{},
		dataLength:  0,
		frameNo:     0,
		windowSize:  r.recvWindow.maxSize,
		flags: PacketFlags{
			ACK:  false,
			FIN:  false,
			REQ:  true,
			RESP: false,
		},
	}
	r.sendQueue <- p.toBytes()
}

func (r *Reliable) Receive(pkt *Packet) error {
	oldAckNo := r.recvWindow.ackNo
	r.sender.recvAck(pkt.ackNo)
	err := r.recvWindow.receive(pkt)
	if oldAckNo != r.recvWindow.ackNo {
		r.sender.send()
	}

	return err
}

func (r *Reliable) Read(b []byte) (n int, err error) {
	// This part gets hard if you want this call to block until data is available.
	//
	// David recommends not making that work until everything else works.
	return r.recvWindow.read(b)
}

func (r *Reliable) Write(b []byte) (n int, err error) {
	// Except with buffering and framing and concurrency control
	return r.sender.write(b)
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
