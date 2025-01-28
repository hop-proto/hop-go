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

	"hop.computer/hop/common"
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
	closed    state = iota
)

// Reliable implements a reliable byte stream
type Reliable struct {
	tType      TubeType
	id         byte
	localAddr  net.Addr
	remoteAddr net.Addr
	// +checklocks:l
	sender     *sender
	recvWindow *receiver
	sendQueue  chan []byte
	// +checklocks:l
	tubeState state
	// +checklocks:l
	lastAckTimer  *time.Timer
	lastAckSent   atomic.Uint32
	lastFrameSent atomic.Uint32
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

	if req {
		p := initiateFrame{
			tubeID:     r.id,
			tubeType:   r.tType,
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
		ticker := time.NewTicker(initialRTT)
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

	r.l.Lock() // required for checklocks
	r.sender.closed.Store(false)
	r.l.Unlock()
}

func (r *Reliable) sendOneFrame(pkt *frame, retransmission bool) {
	pkt.tubeID = r.id
	newAckNo := r.recvWindow.getAck()
	lastAckNo := r.lastAckSent.Load()
	lastFrameNo := r.lastFrameSent.Load()

	// Only send the ACK if either the new ACK is greater or the frame number is greater
	// To not over send the same frame which will be dropped client side
	// TODO (paul) this condition is too long

	if (pkt.dataLength == 0 && (newAckNo != lastAckNo || pkt.frameNo != lastFrameNo || retransmission || pkt.flags.FIN || pkt.flags.RESP)) || pkt.dataLength > 0 {
		pkt.ackNo = newAckNo
		r.lastAckSent.Store(newAckNo)
		r.lastFrameSent.Store(pkt.frameNo) // Update the last frame sent
		pkt.flags.ACK = true
		pkt.flags.REL = true
		r.sendQueue <- pkt.toBytes()
		//logrus.Debugf("SendOneFrame (added to reliable.sendQueue) fno %v, and ack no %v", pkt.frameNo, pkt.ackNo)
	}

	if common.Debug {
		r.log.WithFields(logrus.Fields{
			"frameno": pkt.frameNo,
			"ackno":   pkt.ackNo,
			"ack":     pkt.flags.ACK,
			"fin":     pkt.flags.FIN,
			"dataLen": pkt.dataLength,
		}).Trace("sent packet")
	}
}

// send continuously reads packet from the sends and hands them to the muxer
func (r *Reliable) send() {
	var pkt *frame
	ok := true
	for ok {
		select {
		// find a way of having a logic retransmit ticker time and logic
		case <-r.sender.RetransmitTicker.C:
			r.l.Lock()

			// when sending a file from c1 to c2, the retransmission of an ack is not possible on the point of view of the c2
			// if the c1 mark it a ack and not the c2. The transmission is locked
			numFrames := r.sender.framesToSend(true, 0)

			r.log.WithField("numFrames", numFrames).Trace("retransmitting")
			for i := 0; i < numFrames; i++ {
				// Only retransmit the timed out frames, however will be sent by the windowOpen
				if r.sender.frames[i].queued {
					// Only retransmit the timed out frames, however will be sent by the windowOpen
					r.log.WithFields(logrus.Fields{
						"Frame N°": r.sender.frames[i].frame.frameNo,
						"Ack N°":   r.recvWindow.getAck(),
					}).Trace("Retransmission of")
					//logrus.Debugf("retransmitting frame %v with ack %v", frameEntry.frame.frameNo, r.recvWindow.getAck())
					r.sendOneFrame(r.sender.frames[i].frame, true)
				}
			}

			// Back off RTT if no ACKs were received
			r.sender.RTT *= 2
			r.sender.resetRetransmitTicker()

			r.l.Unlock()

		case <-r.sender.windowOpen:
			r.l.Lock()
			numFrames := r.sender.framesToSend(false, 0)
			r.log.WithField("numFrames", numFrames).Trace("window open")

			for i := 0; i < numFrames; i++ {
				if !r.sender.frames[i].queued {
					//logrus.Debugf("window open, sending frame %v", frameEntry.frame.frameNo)
					r.sendOneFrame(r.sender.frames[i].frame, false)
					r.sender.frames[i].Time = time.Now()
					r.sender.frames[i].queued = true
					r.sender.unacked++
				}
			}
			r.l.Unlock()

		case pkt, ok = <-r.sender.sendQueue:
			if !ok {
				break
			}
			//logrus.Debugf("I get this frame from my sendQueue: fno: %v, ackno %v, window start %v", pkt.frameNo, r.recvWindow.getAck(), r.recvWindow.windowStart)
			r.sendOneFrame(pkt, false)
		}
	}
	r.log.Debug("send ended")
	close(r.sendDone)
}

// receive is called by the muxer for each new packet
func (r *Reliable) receive(pkt *frame) error {
	r.l.Lock()
	defer r.l.Unlock()

	if common.Debug {
		r.log.WithFields(logrus.Fields{
			"frameno": pkt.frameNo,
			"ackno":   pkt.ackNo,
			"ack":     pkt.flags.ACK,
			"fin":     pkt.flags.FIN,
			"dataLen": pkt.dataLength,
		}).Trace("receiving packet")
	}

	// created and closed tubes cannot handle incoming packets
	if r.tubeState == created || r.tubeState == closed {
		if common.Debug {
			r.log.WithFields(logrus.Fields{
				"fin":   pkt.flags.FIN,
				"state": r.tubeState,
			}).Info("receive for tube in bad state")
		}

		return ErrBadTubeState
	}

	// Pass the frame to the receive window
	// TODO (paul) in the reliable tube, this is where the window is incremented and the ack no too
	finProcessed, err := r.recvWindow.receive(pkt)

	// Pass the frame to the sender
	if pkt.flags.ACK {
		r.sender.recvAck(pkt.ackNo)
	}

	// Handle ACK of FIN frame
	if pkt.flags.ACK && r.tubeState != initiated && r.sender.unAckedFramesRemaining() == 0 {
		switch r.tubeState {
		case finWait1:
			r.tubeState = finWait2
			r.log.Debug("got ACK of FIN packet. going from finWait1 to finWait2")
		case closing:
			r.log.Debug("got ACK of FIN packet. going from closing to closed")
			r.enterClosedState()
		case lastAck:
			r.log.Debug("got ACK of FIN packet. going from lastAck to closed")
			r.enterClosedState()
		}
	}

	// Handle FIN frame
	if (pkt.flags.FIN && r.recvWindow.closed.Load()) || finProcessed {
		switch r.tubeState {
		case initiated:
			r.tubeState = closeWait
			r.log.Debug("got FIN packet. going from initiated to closeWait")
		case finWait1:
			r.tubeState = closing
			r.log.Debug("got FIN packet. going from finWait1 to closing")
		case finWait2:
			r.log.Debug("got FIN packet. going from finWait2 to closed")
			r.sender.sendEmptyPacket()
			r.enterClosedState()
		}
		if r.tubeState != closed {
			r.log.Trace("sending ACK of FIN")
			r.sender.sendEmptyPacket()
		}
	}

	// ACK every data packet
	if pkt.dataLength > 0 && r.tubeState != closed && !pkt.flags.FIN {
		r.sender.sendEmptyPacket()
	}

	return err
}

// +checklocks:r.l
func (r *Reliable) enterLastAckState() {
	r.tubeState = lastAck
	r.lastAckTimer = time.AfterFunc(4*r.sender.RTT, func() {
		r.l.Lock()
		defer r.l.Unlock()
		r.log.Warn("timer expired without getting ACK of FIN. going from lastAck to closed")
		r.enterClosedState()
	})
}

// +checklocks:r.l
func (r *Reliable) enterClosedState() {
	if r.tubeState == closed {
		return
	}
	if r.lastAckTimer != nil {
		r.lastAckTimer.Stop()
	}
	r.sender.Close()
	r.recvWindow.Close()
	if r.tubeState != created {
		r.l.Unlock()
		<-r.sendDone
		r.l.Lock()
	}
	close(r.closed)
	r.tubeState = closed
}

func (r *Reliable) receiveInitiatePkt(pkt *initiateFrame) error {
	r.l.Lock()
	defer r.l.Unlock()

	if common.Debug {
		r.log.WithFields(logrus.Fields{
			"frameno": pkt.frameNo,
			"req":     pkt.flags.REQ,
			"resp":    pkt.flags.RESP,
			"rel":     pkt.flags.REL,
			"ack":     pkt.flags.ACK,
			"fin":     pkt.flags.FIN,
		}).Debug("receiving initiate packet")
	}

	if r.tubeState == created {
		r.recvWindow.m.Lock()
		r.recvWindow.ackNo = 1
		r.recvWindow.m.Unlock()
		r.log.Debug("INITIATED!")
		r.tubeState = initiated
		r.sender.recvAck(1)
		close(r.initRecv)
	}

	if pkt.flags.REQ && r.tubeState != closed {
		p := initiateFrame{
			tubeID:     r.id,
			tubeType:   r.tType,
			data:       []byte{},
			dataLength: 0,
			frameNo:    0,
			windowSize: r.recvWindow.getWindowSize(),
			flags: frameFlags{
				REQ:  false,
				RESP: true,
				REL:  true,
				ACK:  true,
				FIN:  false,
			},
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
		r.enterLastAckState()
	default:
		// In this case, Close() has already been called
		return io.EOF
	}

	// Cancel all pending read and write operations
	r.SetReadDeadline(time.Now())
	r.sender.deadline = time.Now()

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
	r.l.Lock()
	defer r.l.Unlock()
	r.sender.deadline = t
	return nil
}
