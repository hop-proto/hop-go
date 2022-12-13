// Package tubes implements the multiplexing of raw data into logical channels of a hop session
package tubes

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// How David would approach this:
//   1. Implement the message framing (seq no, ack no, all that stuff)
//   2. Implement Read and Write assuming no buffering or out of order or anything like that, using the framing
//   3. Buffering
//   4. Concurrency controls (locks)

const retransmitOffset = time.Millisecond * 500

const windowSize = 128

// TubeType represents identifier bytes of Tubes.
type TubeType byte

type state int32

const (
	created   state = iota
	initiated state = iota

	// These states are pulled from the TCP state machine.
	closeWait state = iota
	lastAck   state = iota
	finWait1  state = iota
	finWait2  state = iota
	closing   state = iota
	timeWait  state = iota
	closed    state = iota
)

var errBadTubeState = errors.New("tube in bad state")

// Reliable implements a reliable and receiveWindow tube on top
type Reliable struct {
	closed     chan struct{}
	tType      TubeType
	id         byte
	localAddr  net.Addr
	recvWindow receiver
	remoteAddr net.Addr
	sender     sender
	sendQueue  chan []byte
	// TODO(hosono) probably we shouldn't just have one lock that manages everything
	// +checklocks:l
	tubeState   state
	lastAckSent atomic.Uint32
	initRecv    chan struct{}
	initDone    chan struct{}
	l           sync.Mutex
	log         *logrus.Entry
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

// Reliable tubes are tubes
var _ Tube = &Reliable{}

/* req: whether the tube is requesting to initiate a tube (true), or whether is respondding to an initiation request (false).*/
func (r *Reliable) initiate(req bool) {
	tubeType := r.tType
	notInit := true

	p := initiateFrame{
		tubeID:     r.id,
		tubeType:   tubeType,
		data:       []byte{},
		dataLength: 0,
		frameNo:    0,
		windowSize: r.recvWindow.getWindowSize(),
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
			r.l.Lock()
			notInit = r.tubeState == created
			r.l.Unlock()
		}
	}
	go r.send()
	r.sender.Start()
	close(r.initDone)
}

func (r *Reliable) send() {
	for pkt := range r.sender.sendQueue {
		pkt.tubeID = r.id
		pkt.ackNo = r.recvWindow.getAck()
		r.lastAckSent.Store(pkt.ackNo)
		pkt.flags.ACK = true
		pkt.flags.REL = true
		r.sendQueue <- pkt.toBytes()
	}
}

func (r *Reliable) receive(pkt *frame) error {
	r.l.Lock()
	defer r.l.Unlock()

	// Log the packet
	r.log.WithFields(logrus.Fields{
		"frameno": pkt.frameNo,
		"ackno":   pkt.ackNo,
		"ack":     pkt.flags.ACK,
		"fin":     pkt.flags.FIN,
	}).Trace("receiving packet")

	// created and closed tubes cannot handle incoming packets
	if r.tubeState == created || r.tubeState == closed {
		r.log.WithFields(logrus.Fields{
			"fin":   pkt.flags.FIN,
			"state": r.tubeState,
		}).Errorf("receive for tube in bad state")

		return errBadTubeState
	}

	// Pass the frame to the receive window
	err := r.recvWindow.receive(pkt)

	// Pass the frame to the sender
	if pkt.flags.ACK {
		r.sender.recvAck(pkt.ackNo)
	}

	// Handle ACK of FIN frame
	if pkt.flags.ACK && r.tubeState != initiated && r.sender.unAckedFramesRemaining() == 0 {
		switch r.tubeState {
		case finWait1:
			r.tubeState = finWait2
			r.log.Warn("got ACK of FIN packet. going from finWait1 to finWait2")
		case closing:
			r.tubeState = timeWait
			r.log.Warn("got ACK of FIN packet. going from closing to timeWait")
			r.enterTimeWaitState()
		case lastAck:
			r.tubeState = closed
			r.log.Warn("got ACK of FIN packet. going from lastAck to closed")
			r.enterClosedState()
		}
	}

	// Handle FIN frame
	if pkt.flags.FIN && r.recvWindow.closed.Load() {
		switch r.tubeState {
		case initiated:
			r.tubeState = closeWait
			r.log.Warn("got FIN packet. going from initiated to closeWait")
		case finWait1:
			r.tubeState = closing
			r.log.Warn("got FIN packet. going from finWait1 to closing")
		case finWait2:
			r.tubeState = timeWait
			r.log.Warn("got FIN packet. going from finWait2 to timeWait")
			r.enterTimeWaitState()
		}
		if r.tubeState != closed {
			r.log.Trace("sending ACK of FIN")
			r.sender.sendEmptyPacket()
		}
	}

	// TODO(hosono) is there a wrapping problem here?
	if (r.recvWindow.getAck()-r.lastAckSent.Load()) >= windowSize/2 && !pkt.flags.FIN && r.tubeState != closed {
		r.sender.sendEmptyPacket()
	}

	return err
}

func (r *Reliable) enterTimeWaitState() {
	// TODO(hosono) what should the wait time be?
	// The linux kernel seems to wait 1 minute for connections on the loopback interface.
	// Is that too long for a user to wait? We can't just hand this off to the kernel.

	//TODO(hosono) reset timer on new FINs
	r.sender.stopRetransmit()
	time.AfterFunc(3*time.Second, func() {
		r.l.Lock()
		defer r.l.Unlock()
		r.log.Warn("timer expired. going from timeWait to closed")
		r.enterClosedState()
	})
}

// +checklocks:r.l
func (r *Reliable) enterClosedState() {
	r.sender.Close()
	r.recvWindow.Close()
	r.tubeState = closed
	close(r.closed)
}

func (r *Reliable) receiveInitiatePkt(pkt *initiateFrame) error {
	r.l.Lock()
	defer r.l.Unlock()
	if r.tubeState == created {
		r.recvWindow.m.Lock()
		r.recvWindow.ackNo = 1
		r.recvWindow.m.Unlock()
		r.log.Debug("INITIATED!")
		r.tubeState = initiated
		r.sender.recvAck(1)
		close(r.initRecv)
	}

	return nil
}

func (r *Reliable) Read(b []byte) (n int, err error) {
	<-r.initDone

	r.l.Lock()
	if r.tubeState == created {
		r.l.Unlock()
		return 0, errBadTubeState
	}
	r.l.Unlock()

	return r.recvWindow.read(b)
}

func (r *Reliable) Write(b []byte) (n int, err error) {
	<-r.initDone
	r.l.Lock()
	defer r.l.Unlock()

	switch r.tubeState {
	case created:
		return 0, errBadTubeState
	case initiated, closeWait:
		break
	default:
		return 0, io.EOF
	}

	return r.sender.write(b)
}

// WriteMsgUDP implements the "UDPLike" interface for transport layer NPC. Trying to make tubes have the same funcs as net.UDPConn
func (r *Reliable) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	// This function can skip checking r.tubeState because r.Write() will do that

	length := len(b)
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(length))
	_, e := r.Write(append(h, b...))
	return length, 0, e
}

// ReadMsgUDP implements the "UDPLike" interface for transport layer NPC. Trying to make tubes have the same funcs as net.UDPConn
func (r *Reliable) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	// This function can skip checking r.tubeState because r.Read() will do that

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
	select {
	case <-r.initDone:
		break
	default:
		return errBadTubeState
	}
	r.l.Lock()
	defer r.l.Unlock()

	switch r.tubeState {
	case created:
		return errBadTubeState
	case initiated:
		r.tubeState = finWait1
		r.log.Warn("call to close. going from initiated to finWait1")
	case closeWait:
		r.tubeState = lastAck
		r.log.Warn("call to close. going from closeWait to lastAck")
	default:
		return io.EOF
	}

	// Cancel all pending read and write operations
	r.SetDeadline(time.Now())

	return r.sender.sendFin()
}

// WaitForInit blocks until the Tube is initiated
func (r *Reliable) WaitForInit() {
	<-r.initDone
}

// WaitForClose blocks until the Tube is done closing
func (r *Reliable) WaitForClose() {
	<-r.closed
}

// Type returns tube type
func (r *Reliable) Type() TubeType {
	return r.tType
}

// GetID returns the tube ID
func (r *Reliable) GetID() byte {
	return r.id
}

// IsReliable returns whether the tube is reliable. Always true
func (r *Reliable) IsReliable() bool {
	return true
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
	<-r.initDone
	r.SetReadDeadline(t)
	r.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline (not implemented)
func (r *Reliable) SetReadDeadline(t time.Time) error {
	<-r.initDone
	return r.recvWindow.dataReady.SetDeadline(t)
}

// SetWriteDeadline (not implemented)
func (r *Reliable) SetWriteDeadline(t time.Time) error {
	<-r.initDone
	r.sender.l.Lock()
	defer r.sender.l.Unlock()
	r.sender.deadline = t
	return nil
}
