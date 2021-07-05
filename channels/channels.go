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

// How David would approach this:
//   1. Implement the message framing (seq no, ack no, all that stuff)
//   2. Implement Read and Write assuming no buffering or out of order or anything like that, using the framing
//   3. Buffering
//   4. Concurrency controls (locks)

const RTO = time.Millisecond * 500

const WINDOW_SIZE = 128

// Reliable implements a reliable and receiveWindow channel on top

type Reliable struct {
	closed     bool
	id         byte
	initiated  bool
	localAddr  net.Addr
	m          sync.Mutex
	closedCond sync.Cond
	recvWindow Receiver
	remoteAddr net.Addr
	sender     Sender
	sendQueue  chan []byte
	cType      byte
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

func (r *Reliable) isInitiated() bool {
	r.m.Lock()
	defer r.m.Unlock()
	return r.initiated
}

func (r *Reliable) send() {
	for r.isInitiated() && !r.closed {
		pkt := <-r.sender.sendQueue
		pkt.channelID = r.id
		pkt.ackNo = r.recvWindow.getAck()
		pkt.flags.ACK = true
		logrus.Debug("sending pkt ", pkt.frameNo, pkt.ackNo, pkt.flags.FIN, pkt.flags.ACK)
		r.sendQueue <- pkt.toBytes()
	}
}

func NewReliableChannelWithChannelId(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, channelType byte, channelId byte) *Reliable {
	r := &Reliable{
		id:        channelId,
		initiated: false,
		closed:    false,
		closedCond: sync.Cond{
			L: &sync.Mutex{},
		},
		// TODO (dadrian): uncomment this when transport.Handle and transport.Client implement Local,RemoteAddr()
		// localAddr:  netConn.LocalAddr(),
		// remoteAddr: netConn.RemoteAddr(),
		m: sync.Mutex{},
		recvWindow: Receiver{
			buffer: new(bytes.Buffer),
			bufferCond: sync.Cond{
				L: &sync.Mutex{},
			},
			fragments:   make(PriorityQueue, 0),
			windowSize:  WINDOW_SIZE,
			windowStart: 1,
		},
		sender: Sender{
			ackNo:            1,
			buffer:           make([]byte, 0),
			closed:           false,
			frameDataLengths: make(map[uint32]uint16),
			frameNo:          1,
			RTO:              RTO,
			sendQueue:        make(chan *Frame),
			windowSize:       WINDOW_SIZE,
		},
		sendQueue: sendQueue,
		cType:     channelType,
	}
	r.recvWindow.closedCond = &r.closedCond
	r.recvWindow.init()
	go r.initiate(false)
	return r
}

func NewReliableChannel(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, cType byte) (*Reliable, error) {
	cid := []byte{0}
	n, err := rand.Read(cid)
	if err != nil || n != 1 {
		return nil, err
	}
	r := &Reliable{
		id:        cid[0],
		initiated: false,
		closed:    false,
		// TODO (dadrian): uncomment this when transport.Handle and transport.Client implement Local,RemoteAddr()
		// localAddr:  netConn.LocalAddr(),
		// remoteAddr: netConn.RemoteAddr(),
		m: sync.Mutex{},
		closedCond: sync.Cond{
			L: &sync.Mutex{},
		},
		recvWindow: Receiver{
			buffer: new(bytes.Buffer),
			bufferCond: sync.Cond{
				L: &sync.Mutex{},
			},
			fragments:   make(PriorityQueue, 0),
			windowSize:  WINDOW_SIZE,
			windowStart: 1,
		},
		sender: Sender{
			ackNo:            1,
			buffer:           make([]byte, 0),
			closed:           false,
			frameDataLengths: make(map[uint32]uint16),
			frameNo:          1,
			RTO:              RTO,
			sendQueue:        make(chan *Frame),
			windowSize:       WINDOW_SIZE,
		},
		sendQueue: sendQueue,
		cType:     cType,
	}
	r.recvWindow.closedCond = &r.closedCond
	r.recvWindow.init()
	go r.initiate(true)
	return r, nil
}

/* req: whether the channel is requesting to initiate a channel (true), or whether is respondding to an initiation request (false).*/
func (r *Reliable) initiate(req bool) {
	channelType := byte(0)
	not_init := true

	for not_init {
		p := InitiateFrame{
			channelID:   r.id,
			channelType: channelType,
			data:        []byte{},
			dataLength:  0,
			frameNo:     0,
			windowSize:  r.recvWindow.windowSize,
			flags: FrameFlags{
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
	go r.sender.retransmit()
	go r.send()
}

func (r *Reliable) receive(pkt *Frame) error {
	if !r.initiated {
		logrus.Error("receiving non-initiate channel frames when not initiated")
		return errors.New("receiving non-initiate channel frames when not initiated")
	}
	r.closedCond.L.Lock()
	if pkt.flags.ACK {
		r.sender.recvAck(pkt.ackNo)
	}
	r.closedCond.Signal()
	r.closedCond.L.Unlock()
	err := r.recvWindow.receive(pkt)

	return err
}

func (r *Reliable) receiveInitiatePkt(pkt *InitiateFrame) error {
	r.m.Lock()
	defer r.m.Unlock()

	if !r.initiated {
		r.recvWindow.m.Lock()
		r.recvWindow.ackNo = 1
		r.recvWindow.m.Unlock()
		logrus.Debug("INITIATED! ", pkt.flags.REQ, " ", pkt.flags.RESP)
		r.initiated = true
		r.sender.recvAck(1)
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
	r.m.Lock()
	if r.closed {
		r.m.Unlock()
		return errors.New("channel already closed")
	}
	r.m.Unlock()
	err := r.sender.close()
	if err != nil {
		return err
	}
	logrus.Info("STARTNG CLOSE")

	time.Sleep(time.Second)
	// Wait until the other end of the connection has received the FIN packet from the other side.
	start := time.Now()
	go func() {
		timer := time.NewTimer(time.Second * 5)
		<-timer.C
		r.closedCond.L.Lock()
		r.closedCond.Signal()
		r.closedCond.L.Unlock()
	}()
	r.closedCond.L.Lock()
	for {

		t := time.Now()
		elapsed := t.Sub(start)
		logrus.Info("waiting: ", r.sender.unsentFramesRemaining(), r.recvWindow.closed, elapsed.Seconds())

		if (!r.sender.unsentFramesRemaining() && r.recvWindow.closed) || elapsed.Seconds() > 5 {
			break
		}
		r.closedCond.Wait()
	}
	r.closedCond.L.Unlock()

	logrus.Info("CLOSED! WOOHOO")
	r.m.Lock()
	r.closed = true
	r.m.Unlock()
	return nil
}

func (r *Reliable) Type() byte {
	return r.cType
}

func (r *Reliable) LocalAddr() net.Addr {
	return r.localAddr
}

func (r *Reliable) RemoteAddr() net.Addr {
	return r.remoteAddr
}

func (r *Reliable) SetDeadline(t time.Time) error {
	// TODO
	panic("implement me")
}

func (r *Reliable) SetReadDeadline(t time.Time) error {
	// TODO
	panic("implement me")
}

func (r *Reliable) SetWriteDeadline(t time.Time) error {
	// TODO
	panic("implement me")
}
