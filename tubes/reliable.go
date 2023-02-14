// Package tubes implements the multiplexing of raw data into logical channels of a hop session
package tubes

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

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

// Reliable implements a reliable byte stream
type Reliable struct {
	tType      TubeType
	id         byte
	localAddr  net.Addr
	remoteAddr net.Addr
	sender     sender
	recvWindow receiver
	sendQueue  chan []byte
	// +checklocks:l
	tubeState     state
	timeWaitTimer *time.Timer
	lastAckSent   atomic.Uint32
	closed        chan struct{}
	initRecv      chan struct{}
	initDone      chan struct{}
	sendDone      chan struct{}
	l             sync.Mutex
	log           *logrus.Entry
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

// Reliable tubes are tubes
var _ Tube = &Reliable{}

// req: whether the tube is requesting to initiate a tube (true), or whether is respondding to an initiation request (false).
func (r *Reliable) initiate(req bool) {
	defer close(r.initDone)
	notInit := true
	var flags byte
	if req {
		flags |= FlagREQ
	} else {
		flags |= FlagRESP
	}
	flags |= (FlagREL | FlagACK)

	if req {
		p := initiateFrame{
			tubeID:     r.id,
			tubeType:   r.tType,
			data:       []byte{},
			dataLength: 0,
			frameNo:    0,
			windowSize: r.recvWindow.getWindowSize(),
			flags:      flags,
		}
		ticker := time.NewTicker(retransmitOffset)
		for notInit {
			r.sendQueue <- p.toBytes()
			select {
			case <-ticker.C:
				r.log.Info("init rto exceeded")
				continue
			case <-r.initRecv:
				r.l.Lock()
				notInit = r.tubeState == created
				r.l.Unlock()
			case <-r.closed:
				return
			}
		}
	}

	go r.send()
	r.sender.Start()
}

// send continuously reads packet from the sends and hands them to the muxer
func (r *Reliable) send() {
	for pkt := range r.sender.sendQueue {
		pkt.tubeID = r.id
		pkt.ackNo = r.recvWindow.getAck()
		r.lastAckSent.Store(pkt.ackNo)
		pkt.flags |= (FlagACK | FlagREL)
		r.sendQueue <- pkt.toBytes()

		r.log.WithFields(logrus.Fields{
			"frameno": pkt.frameNo,
			"ackno":   pkt.ackNo,
			"ack":     pkt.hasFlags(FlagACK),
			"fin":     pkt.hasFlags(FlagFIN),
			"dataLen": pkt.dataLength,
		}).Trace("sent packet")
	}
	r.log.Debug("send ended")
	close(r.sendDone)
}

// receive is called by the muxer for each new packet
func (r *Reliable) receive(pkt *frame) error {
	r.l.Lock()
	defer r.l.Unlock()

	// Log the packet
	r.log.WithFields(logrus.Fields{
		"frameno": pkt.frameNo,
		"ackno":   pkt.ackNo,
		"ack":     pkt.hasFlags(FlagACK),
		"fin":     pkt.hasFlags(FlagFIN),
		"dataLen": pkt.dataLength,
	}).Trace("receiving packet")

	// created and closed tubes cannot handle incoming packets
	if r.tubeState == created || r.tubeState == closed {
		r.log.WithFields(logrus.Fields{
			"fin":   pkt.hasFlags(FlagFIN),
			"state": r.tubeState,
		}).Info("receive for tube in bad state")

		return ErrBadTubeState
	}

	// Pass the frame to the receive window
	finProcessed, err := r.recvWindow.receive(pkt)

	// Pass the frame to the sender
	if pkt.hasFlags(FlagACK) {
		r.sender.recvAck(pkt.ackNo)
	}

	// Handle ACK of FIN frame
	if pkt.hasFlags(FlagACK) && r.tubeState != initiated && r.sender.unAckedFramesRemaining() == 0 {
		switch r.tubeState {
		case finWait1:
			r.tubeState = finWait2
			r.log.Debug("got ACK of FIN packet. going from finWait1 to finWait2")
		case closing:
			r.log.Debug("got ACK of FIN packet. going from closing to timeWait")
			r.enterTimeWaitState()
		case lastAck:
			r.log.Debug("got ACK of FIN packet. going from lastAck to closed")
			r.enterClosedState()
		}
	}

	// Handle FIN frame
	if (pkt.hasFlags(FlagFIN) && r.recvWindow.closed.Load()) || finProcessed {
		switch r.tubeState {
		case initiated:
			r.tubeState = closeWait
			r.log.Debug("got FIN packet. going from initiated to closeWait")
		case finWait1:
			r.tubeState = closing
			r.log.Debug("got FIN packet. going from finWait1 to closing")
		case finWait2:
			r.log.Debug("got FIN packet. going from finWait2 to timeWait")
			r.enterTimeWaitState()
		case timeWait:
			r.log.Debug("got FIN packet. reseting timeWait timer")
			r.timeWaitTimer.Reset(timeWaitTime)
		}
		if r.tubeState != closed {
			r.log.Trace("sending ACK of FIN")
			r.sender.sendEmptyPacket()
		}
	}

	// ACK every data packet
	if pkt.dataLength > 0 && r.tubeState != closed && !pkt.hasFlags(FlagFIN) {
		r.sender.sendEmptyPacket()
	}

	return err
}

// +checklocks:r.l
func (r *Reliable) enterTimeWaitState() {
	r.tubeState = timeWait
	r.sender.stopRetransmit()
	r.timeWaitTimer = time.AfterFunc(timeWaitTime, func() {
		r.l.Lock()
		defer r.l.Unlock()
		r.log.Debug("timer expired. going from timeWait to closed")
		r.enterClosedState()
	})
}

// +checklocks:r.l
func (r *Reliable) enterClosedState() {
	if r.tubeState == closed {
		return
	}
	r.sender.Close()
	r.recvWindow.Close()
	if r.tubeState != created {
		<-r.sendDone
	}
	close(r.closed)
	r.tubeState = closed
}

func (r *Reliable) receiveInitiatePkt(pkt *initiateFrame) error {
	r.l.Lock()
	defer r.l.Unlock()

	// Log the packet
	r.log.WithFields(logrus.Fields{
		"frameno": pkt.frameNo,
		"req":     pkt.hasFlags(FlagREQ),
		"resp":    pkt.hasFlags(FlagRESP),
		"rel":     pkt.hasFlags(FlagREL),
		"ack":     pkt.hasFlags(FlagACK),
		"fin":     pkt.hasFlags(FlagFIN),
	}).Debug("receiving initiate packet")

	if r.tubeState == created {
		r.recvWindow.m.Lock()
		r.recvWindow.ackNo = 1
		r.recvWindow.m.Unlock()
		r.log.Debug("INITIATED!")
		r.tubeState = initiated
		r.sender.recvAck(1)
		close(r.initRecv)
	}

	if pkt.hasFlags(FlagREQ) && r.tubeState != closed {
		p := initiateFrame{
			tubeID:     r.id,
			tubeType:   r.tType,
			data:       []byte{},
			dataLength: 0,
			frameNo:    0,
			windowSize: r.recvWindow.getWindowSize(),
			flags:      FlagRESP | FlagREL | FlagACK,
		}
		r.sendQueue <- p.toBytes()
	}

	return nil
}

// Read satisfies the net.Conn interface
func (r *Reliable) Read(b []byte) (n int, err error) {
	<-r.initDone

	r.l.Lock()
	if r.tubeState == created {
		r.l.Unlock()
		return 0, ErrBadTubeState
	}
	r.l.Unlock()

	return r.recvWindow.read(b)
}

// Write satisfies the net.Conn interface
func (r *Reliable) Write(b []byte) (n int, err error) {
	<-r.initDone
	r.l.Lock()
	defer r.l.Unlock()

	switch r.tubeState {
	case created:
		return 0, ErrBadTubeState
	case initiated, closeWait:
		break
	default:
		return 0, io.EOF
	}

	return r.sender.write(b)
}

// WriteMsgUDP implements the UDPLike interface.
// While Reliable tubes do implement the UDPLike interface, Unreliable tubes are a better drop in replacement for UDP.
func (r *Reliable) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	// This function can skip checking r.tubeState because r.Write() will do that
	length := len(b)
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(length))
	_, e := r.Write(append(h, b...))
	return length, 0, e
}

// ReadMsgUDP implements the UDPLike interface.
// While Reliable tubes do implement the UDPLike interface, Unreliable tubes are a better drop in replacement for UDP.
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
	case <-r.closed:
		break
	}

	r.l.Lock()
	defer r.l.Unlock()

	switch r.tubeState {
	case created:
		r.log.WithField("state", r.tubeState).Warn("tried to close tube in bad state")
		return ErrBadTubeState
	case initiated:
		r.tubeState = finWait1
		r.log.Debug("call to close. going from initiated to finWait1")
	case closeWait:
		r.tubeState = lastAck
		r.log.Debug("call to close. going from closeWait to lastAck")
	default:
		// In this case, Close() has already been called
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
	<-r.initDone
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

// getLog returns the logging context for the tube
func (r *Reliable) getLog() *logrus.Entry {
	return r.log
}

// LocalAddr returns the local address for the tube
func (r *Reliable) LocalAddr() net.Addr {
	return r.localAddr
}

// RemoteAddr returns the remote address for the tube
func (r *Reliable) RemoteAddr() net.Addr {
	return r.remoteAddr
}

// SetDeadline implements the net.Conn interface.
// All read and write operations past the deadline will return an error.
func (r *Reliable) SetDeadline(t time.Time) error {
	<-r.initDone
	r.SetReadDeadline(t)
	r.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline implements the net.Conn interface.
// All read operations past the deadline will return an error.
func (r *Reliable) SetReadDeadline(t time.Time) error {
	<-r.initDone
	return r.recvWindow.dataReady.SetDeadline(t)
}

// SetWriteDeadline implements the net.Conn interface.
// All write operations past the deadline will return an error.
func (r *Reliable) SetWriteDeadline(t time.Time) error {
	<-r.initDone
	r.sender.l.Lock()
	defer r.sender.l.Unlock()
	r.sender.deadline = t
	return nil
}
