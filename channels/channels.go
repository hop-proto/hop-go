package channels

import (
	"bytes"
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

const RTO = time.Millisecond * 10

// Reliable implements a reliable and receiveWindow channel on top

type Reliable struct {
	id         byte
	initiated  bool
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
		pkt.channelID = r.id
		r.recvWindow.m.Lock()
		pkt.ackNo = uint32(r.recvWindow.ackNo)
		r.recvWindow.m.Unlock()
		r.sendQueue <- pkt.toBytes()
		// logrus.Info("SENT PACKET", pkt.frameNo, pkt.ackNo, pkt.flags, pkt.data)
	}
}

func NewReliableChannelWithChannelId(underlying transport.MsgConn, sendQueue chan []byte, windowSize uint16, channelId byte) *Reliable {
	r := &Reliable{
		id:        channelId,
		initiated: false,
		closed:    false,
		m:         sync.Mutex{},
		recvWindow: ReceiveWindow{
			buffer:      new(bytes.Buffer),
			fragments:   make(PriorityQueue, 0),
			maxSize:     windowSize,
			windowStart: 1,
		},
		sender: Sender{
			ackNo:            1,
			buffer:           make([]byte, 0),
			frameDataLengths: make(map[uint32]uint16),
			frameNo:          1,
			RTO:              RTO,
			sendQueue:        make(chan *Packet),
			windowSize:       1,
		},
		sendQueue: sendQueue,
	}
	r.recvWindow.init()
	go r.initiate(false)
	return r
}

func NewReliableChannel(underlying transport.MsgConn, sendQueue chan []byte, windowSize uint16) (*Reliable, error) {
	cid := []byte{0}
	n, err := rand.Read(cid)
	if err != nil || n != 1 {
		return nil, err
	}
	r := &Reliable{
		id:        cid[0],
		initiated: false,
		closed:    false,
		m:         sync.Mutex{},
		recvWindow: ReceiveWindow{
			buffer:      new(bytes.Buffer),
			fragments:   make(PriorityQueue, 0),
			maxSize:     windowSize,
			windowStart: 1,
		},
		sender: Sender{
			ackNo:            1,
			buffer:           make([]byte, 0),
			frameDataLengths: make(map[uint32]uint16),
			frameNo:          1,
			RTO:              RTO,
			sendQueue:        make(chan *Packet),
			windowSize:       1,
		},
		sendQueue: sendQueue,
	}
	r.recvWindow.init()
	go r.initiate(true)
	return r, nil
}

/* req: whether the channel is requesting to initiate a channel (true), or whether is respondding to an initiation request (false).*/
func (r *Reliable) initiate(req bool) {
	channelType := byte(0)
	not_init := true

	for not_init {
		p := InitiatePacket{
			channelID:   r.id,
			channelType: channelType,
			data:        []byte{},
			dataLength:  0,
			frameNo:     0,
			windowSize:  r.recvWindow.maxSize,
			flags: PacketFlags{
				ACK:  true,
				FIN:  false,
				REQ:  req,
				RESP: !req,
			},
		}
		r.sendQueue <- p.toBytes()
		r.m.Lock()
		not_init = !r.initiated
		r.m.Unlock()
		timer := time.NewTimer(RTO)
		<-timer.C
	}
	logrus.Info("FINISHED INIT ", req, " ack no ", r.sender.ackNo)
	go r.sender.retransmit()
	go r.send()
}

func (r *Reliable) Receive(pkt *Packet) error {
	if !r.initiated {
		logrus.Error("receiving non-initiate channel frames when not initiated")
		return errors.New("receiving non-initiate channel frames when not initiated")
	}

	if r.closed {
		logrus.Error("receiving channel frames when closed")
		return errors.New("receiving channel frames when closed")
	}

	r.recvWindow.m.Lock()
	oldAckNo := r.recvWindow.ackNo

	r.sender.recvAck(pkt.ackNo)

	err := r.recvWindow.receive(pkt)

	newAckNo := r.recvWindow.ackNo
	r.recvWindow.m.Unlock()

	if oldAckNo != newAckNo {
		r.sender.send()
	}

	return err
}

func (r *Reliable) ReceiveInitiatePkt(pkt *InitiatePacket) error {
	r.m.Lock()
	defer r.m.Unlock()
	validState := !r.initiated && !r.closed

	if validState {
		r.recvWindow.m.Lock()
		r.recvWindow.ackNo = 1
		r.recvWindow.m.Unlock()
		r.initiated = true
		r.sender.recvAck(1)
		logrus.Info("set ackNo ", r.sender.ackNo)
	}

	return nil
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
	// TODO:
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
