// Package tubes implements the multiplexing of raw data into logical channels of a hop session
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

	"hop.computer/hop/common"
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
	closing     chan struct{}
	finReceived chan struct{}
	tType       TubeType
	id          byte
	localAddr   net.Addr
	m           sync.Mutex
	recvWindow  receiver
	remoteAddr  net.Addr
	sender      sender
	sendQueue   chan []byte
	// +checklocks:m
	tubeState state // TODO(hosono) this could just be atomic
	initRecv  chan struct{}
	muxer     *Muxer
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

func (r *Reliable) closer() {
	for {
		if r.recvWindow.closed.Load() {
			break
		}
		<-r.finReceived
	}
	r.Close()
}

func newReliableTubeWithTubeID(muxer *Muxer, tubeType TubeType, tubeID byte) *Reliable {
	r := makeTube(muxer, tubeType, tubeID)
	go r.initiate(false)
	return r
}

func makeTube(muxer *Muxer, tType TubeType, tubeID byte) *Reliable {
	r := &Reliable{
		muxer:       muxer,
		id:          tubeID,
		tubeState:   created,
		localAddr:   muxer.underlying.LocalAddr(),
		remoteAddr:  muxer.underlying.RemoteAddr(),
		m:           sync.Mutex{},
		initRecv:    make(chan struct{}),
		closing:     make(chan struct{}, 1),
		finReceived: make(chan struct{}, 1),
		recvWindow: receiver{
			dataReady:   common.NewDeadlineChan[struct{}](1),
			buffer:      new(bytes.Buffer),
			fragments:   make(PriorityQueue, 0),
			windowSize:  windowSize,
			windowStart: 1,
		},
		sender: sender{
			ackNo:  1,
			buffer: make([]byte, 0),
			// closed defaults to false
			finSent:          false,
			frameDataLengths: make(map[uint32]uint16),
			frameNo:          1,
			RTOTicker:        time.NewTicker(retransmitOffset),
			RTO:              retransmitOffset,
			windowSize:       windowSize,
		},
		sendQueue: muxer.sendQueue,
		tType:     tType,
	}
	r.sender.tube = r
	r.recvWindow.finReceived = r.finReceived
	r.recvWindow.init()
	return r
}

func newReliableTube(muxer *Muxer, tType TubeType) (*Reliable, error) {
	cid := []byte{0}
	n, err := rand.Read(cid) // TODO(hosono) make sure there are no tube conflicts
	if err != nil || n != 1 {
		return nil, err
	}
	r := makeTube(muxer, tType, cid[0])
	go r.initiate(true)
	return r, nil
}

/* req: whether the tube is requesting to initiate a tube (true), or whether is respondding to an initiation request (false).*/
func (r *Reliable) initiate(req bool) {
	//logrus.Errorf("Tube %d initiated", r.id)
	tubeType := r.tType
	notInit := true

	p := initiateFrame{
		tubeID:     r.id,
		tubeType:   tubeType,
		data:       []byte{},
		dataLength: 0,
		frameNo:    0,
		windowSize: r.recvWindow.windowSize,
		flags: frameFlags{
			REQ:  req,
			RESP: !req,
			REL:  true,
			ACK:  true,
			FIN:  false,
		},
	}
	ticker := time.NewTicker(retransmitOffset)
	for notInit {
		r.sendQueue <- p.toBytes()
		select {
		case <-ticker.C:
			continue
		case <-r.initRecv:
			r.m.Lock()
			notInit = r.tubeState == created
			r.m.Unlock()
		}
	}
	go r.sender.retransmit()
	//go r.closer()
}

func (r *Reliable) receive(pkt *frame) error {
	r.m.Lock()
	defer r.m.Unlock()
	if r.tubeState != initiated {
		//logrus.Error("receiving non-initiate tube frames when not initiated")
		return errors.New("receiving non-initiate tube frames when not initiated")
	}
	logrus.Tracef("receving packet. ackno: %d, ack? %t", pkt.ackNo, pkt.flags.ACK)
	if pkt.flags.ACK {
		r.sender.recvAck(pkt.ackNo)
	}
	select {
	case r.closing <- struct{}{}:
		break
	default:
		break
	}
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
		close(r.initRecv)
	}

	return nil
}

func (r *Reliable) checkInitiated() (error) {
	r.m.Lock()
	defer r.m.Unlock()
	if r.tubeState != initiated {
		return errors.New("tube not initiated")
	}
	return nil
}

func (r *Reliable) WaitForInitiated() {
	<-r.initRecv
}

func (r *Reliable) Read(b []byte) (n int, err error) {
	err = r.checkInitiated()
	if err != nil {
		return 0, err
	}
	return r.recvWindow.read(b)
}

func (r *Reliable) Write(b []byte) (n int, err error) {
	err = r.checkInitiated()
	if err != nil {
		return 0, err
	}
	return r.sender.write(b)
}

// WriteMsgUDP implements the "UDPLike" interface for transport layer NPC. Trying to make tubes have the same funcs as net.UDPConn
func (r *Reliable) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	err = r.checkInitiated()
	if err != nil {
		return
	}
	length := len(b)
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(length))
	_, e := r.Write(append(h, b...))
	return length, 0, e
}

// ReadMsgUDP implements the "UDPLike" interface for transport layer NPC. Trying to make tubes have the same funcs as net.UDPConn
func (r *Reliable) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	err = r.checkInitiated()
	if err != nil {
		return
	}
	h := make([]byte, 2)
	_, e := io.ReadFull(r, h)
	if e != nil {
		return 0, 0, 0, nil, e
	}
	length := binary.BigEndian.Uint16(h)
	data := make([]byte, length)
	_, e = io.ReadFull(r, data)
	n = copy(b, data)
	return n, 0, 0, nil, e
}

// Close handles closing reliable tubes
func (r *Reliable) Close() (err error) {
	r.m.Lock()
	if r.tubeState == closed {
		r.m.Unlock()
		return io.EOF
	}
	r.m.Unlock()
	err = r.checkInitiated()
	if err != nil {
		return err
	}
	//r.m.Lock()
	//r.tubeState = closeStart
	//r.m.Unlock()
	err = r.sender.sendFin()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	logrus.Debugf("Starting close of tube %d", r.id)

	// Wait until the other end of the connection has received the FIN packet from the other side.
closeLoop:
	for {
		select {
		case <-r.closing:
			if !r.sender.unsentFramesRemaining() && r.recvWindow.closed.Load() {
				logrus.Debugf("sent all frames and got fin for tube %d", r.id)
				break closeLoop
			} else {
				logrus.Debugf("closing. packets left to ack: %d", len(r.sender.frames))
			}
		}
	}
	r.sender.Close()
	r.recvWindow.Close()
	logrus.Debugf("closed tube: %v", r.id)
	r.m.Lock()
	r.tubeState = closed
	r.m.Unlock()

	return nil
}

// Type returns tube type
func (r *Reliable) Type() TubeType {
	return r.tType
}

// LocalAddr returns the local address for the tube
func (r *Reliable) LocalAddr() net.Addr {
	return r.localAddr
}

// RemoteAddr returns the remote address for the tube
func (r *Reliable) RemoteAddr() net.Addr {
	return r.remoteAddr
}

// SetDeadline (not implemented)
func (r *Reliable) SetDeadline(t time.Time) error {
	r.SetReadDeadline(t)
	r.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline (not implemented)
func (r *Reliable) SetReadDeadline(t time.Time) error {
	return r.recvWindow.dataReady.SetDeadline(t)
}

// SetWriteDeadline (not implemented)
func (r *Reliable) SetWriteDeadline(t time.Time) error {
	r.sender.l.Lock()
	defer r.sender.l.Unlock()
	r.sender.deadline = t
	return nil
}
