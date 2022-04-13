//Package tubes implements the multiplexing of raw data into logical channels of a hop session
package tubes

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
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

const retransmitOffset = time.Millisecond * 500

const windowSize = 128

type state int

// TubeType represents identifier bytes of Tubes.
type TubeType byte

const (
	created    state = iota
	initiated  state = iota
	closeStart state = iota
	closed     state = iota
)

// Reliable implements a reliable and receiveWindow tube on top
type Reliable struct {
	closedCond sync.Cond
	tType      TubeType
	id         byte
	localAddr  net.Addr
	m          sync.Mutex
	recvWindow receiver
	remoteAddr net.Addr
	sender     sender
	sendQueue  chan []byte
	tubeState  state
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

func (r *Reliable) getState() state {
	r.m.Lock()
	defer r.m.Unlock()
	return r.tubeState
}

func (r *Reliable) send() {
	for r.getState() == initiated || r.getState() == closeStart {
		pkt := <-r.sender.sendQueue
		pkt.tubeID = r.id
		pkt.ackNo = r.recvWindow.getAck()
		pkt.flags.ACK = true
		logrus.Debug("sending pkt ", pkt.frameNo, pkt.ackNo, pkt.flags.FIN, pkt.flags.ACK)
		r.sendQueue <- pkt.toBytes()
	}
}

func newReliableTubeWithTubeID(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tubeType TubeType, tubeID byte) *Reliable {
	r := makeTube(underlying, netConn, sendQueue, tubeType, tubeID)
	go r.initiate(false)
	return r
}

func makeTube(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tType TubeType, tubeID byte) *Reliable {
	r := &Reliable{
		id:        tubeID,
		tubeState: created,
		// TODO (dadrian): uncomment this when transport.Handle and transport.Client implement Local,RemoteAddr()
		// localAddr:  netConn.LocalAddr(),
		// remoteAddr: netConn.RemoteAddr(),
		m: sync.Mutex{},
		closedCond: sync.Cond{
			L: &sync.Mutex{},
		},
		recvWindow: receiver{
			buffer: new(bytes.Buffer),
			bufferCond: sync.Cond{
				L: &sync.Mutex{},
			},
			fragments:   make(PriorityQueue, 0),
			windowSize:  windowSize,
			windowStart: 1,
		},
		sender: sender{
			ackNo:            1,
			buffer:           make([]byte, 0),
			closed:           false,
			finSent:          false,
			frameDataLengths: make(map[uint32]uint16),
			frameNo:          1,
			RTO:              retransmitOffset,
			sendQueue:        make(chan *frame),
			windowSize:       windowSize,
			ret:              make(chan int),
		},
		sendQueue: sendQueue,
		tType:     tType,
	}
	r.recvWindow.closedCond = &r.closedCond
	r.recvWindow.init()
	return r
}

func newReliableTube(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tType TubeType) (*Reliable, error) {
	cid := []byte{0}
	n, err := rand.Read(cid)
	if err != nil || n != 1 {
		return nil, err
	}
	r := makeTube(underlying, netConn, sendQueue, tType, cid[0])
	go r.initiate(true)
	return r, nil
}

/* req: whether the tube is requesting to initiate a tube (true), or whether is respondding to an initiation request (false).*/
func (r *Reliable) initiate(req bool) {
	tubeType := r.tType
	notInit := true

	for notInit {
		p := initiateFrame{
			tubeID:     r.id,
			tubeType:   tubeType,
			data:       []byte{},
			dataLength: 0,
			frameNo:    0,
			windowSize: r.recvWindow.windowSize,
			flags: frameFlags{
				ACK:  true,
				FIN:  false,
				REQ:  req,
				RESP: !req,
			},
		}
		r.sendQueue <- p.toBytes()
		r.m.Lock()
		notInit = r.tubeState == created
		r.m.Unlock()
		timer := time.NewTimer(retransmitOffset)
		<-timer.C
	}
	go r.sender.retransmit()
	go r.send()
}

func (r *Reliable) receive(pkt *frame) error {
	if r.tubeState != initiated {
		//logrus.Error("receiving non-initiate tube frames when not initiated")
		return errors.New("receiving non-initiate tube frames when not initiated")
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

func (r *Reliable) receiveInitiatePkt(pkt *initiateFrame) error {
	r.m.Lock()
	defer r.m.Unlock()

	if r.tubeState == created {
		r.recvWindow.m.Lock()
		r.recvWindow.ackNo = 1
		r.recvWindow.m.Unlock()
		//logrus.Debug("INITIATED! ", pkt.flags.REQ, " ", pkt.flags.RESP)
		r.tubeState = initiated
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

//TODO(baumanl): if Reliable tubes implement io.Reader() (with Read behaving as specified) then
//this function is not needed because io.Copy() will use dst.ReadFrom(src *Reliable) instead of src.WriteTo(dst)

//WriteTo interface for io.Copy() to work
func (r *Reliable) WriteTo(w io.Writer) (n int64, err error) {
	var count int64
	for {
		b := make([]byte, 1)
		n, e := r.Read(b)
		count += int64(n)
		if e != nil {
			return count, e
		}
		_, e = w.Write(b)
		//TODO(baumanl): finalize that this function closes correctly according to WriteTo interface
		if e != nil {
			return count, e
		}
	}
}

//WriteMsgUDP implements the "UDPLike" interface for transport layer NPC. Trying to make tubes have the same funcs as net.UDPConn
func (r *Reliable) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	length := len(b)
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(length))
	_, e := r.Write(append(h, b...))
	return length, 0, e
}

//ReadMsgUDP implements the "UDPLike" interface for transport layer NPC. Trying to make tubes have the same funcs as net.UDPConn
func (r *Reliable) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	h := make([]byte, 2)
	_, e := r.Read(h)
	if e != nil {
		return 0, 0, 0, nil, e
	}
	length := binary.BigEndian.Uint16(h)
	data := make([]byte, length)
	_, e = r.Read(data)
	n = copy(b, data)
	return n, 0, 0, nil, e
}

//Close handles closing reliable tubes
func (r *Reliable) Close() error {
	r.m.Lock()
	name := r.id
	if r.tubeState == closed {
		r.m.Unlock()
		return errors.New("tube already closed")
	}
	r.m.Unlock()
	err := r.sender.sendFin()
	if err != nil {
		return err
	}
	logrus.Debug("Starting close of ", r.id)

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
		logrus.Debug("waiting: ", r.sender.unsentFramesRemaining(), r.recvWindow.closed, elapsed.Seconds())

		if elapsed.Seconds() > 5 || (!r.sender.unsentFramesRemaining() && r.recvWindow.closed) {
			logrus.Debug("Breaking out! ", r.id)
			break
		}
		r.closedCond.Wait()
	}
	r.closedCond.L.Unlock()
	r.sender.close()
	logrus.Debugf("closed tube: %v", name)
	r.m.Lock()
	r.tubeState = closed
	r.m.Unlock()

	return nil
}

//Type returns tube type
func (r *Reliable) Type() TubeType {
	return r.tType
}

//LocalAddr returns tube local address
func (r *Reliable) LocalAddr() net.Addr {
	return r.localAddr
}

//RemoteAddr returns r.remoteAddr
func (r *Reliable) RemoteAddr() net.Addr {
	return r.remoteAddr
}

//SetDeadline (not implemented)
func (r *Reliable) SetDeadline(t time.Time) error {
	// TODO
	panic("implement me")
}

//SetReadDeadline (not implemented)
func (r *Reliable) SetReadDeadline(t time.Time) error {
	// TODO
	panic("implement me")
}

//SetWriteDeadline (not implemented)
func (r *Reliable) SetWriteDeadline(t time.Time) error {
	// TODO
	panic("implement me")
}
