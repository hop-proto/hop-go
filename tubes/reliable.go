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
	// +checklocksignore
	tType      TubeType
	id         byte
	localAddr  net.Addr
	remoteAddr net.Addr
	// +checklocks:l
	sender            *sender
	recvWindow        *receiver
	sendQueue         chan []byte
	prioritySendQueue chan []byte
	// +checklocks:l
	tubeState state
	// +checklocks:l
	lastAckTimer  *time.Timer
	lastAckSent   atomic.Uint32
	lastFrameSent atomic.Uint32
	unsend        uint16

	closed   chan struct{}
	initRecv chan struct{}
	initDone chan struct{}
	sendDone chan struct{}
	l        sync.Mutex
	log      *logrus.Entry
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
	} else {
		<-r.initRecv
	}

	go r.send()

	r.l.Lock() // required for checklocks
	r.sender.closed.Store(false)
	r.l.Unlock()
}

func (r *Reliable) sendOneFrame(pkt *frame, retransmission bool) {
	ackNo := r.recvWindow.getAck()
	lastFrameNo := r.lastFrameSent.Load()
	lastAckNo := r.lastAckSent.Load()

	pkt.tubeID = r.id
	pkt.ackNo = ackNo
	pkt.flags.REL = true

	// The ACK flag must be used only to signal an acknowledgement.
	// At this point only the frames with a dataLength of 0 are
	// considered as being regular acknowledgements (not RTR).
	if pkt.dataLength == 0 {
		pkt.flags.ACK = true
	}

	// Limit the retransmission of ACKs to the last value loaded through r.recvWindow.getAck()
	if (pkt.dataLength > 0 ||
		(pkt.dataLength == 0 && (ackNo != lastAckNo || pkt.frameNo != lastFrameNo ||
			retransmission || pkt.flags.FIN || pkt.flags.RESP))) || r.unsend == 10 { // based on best practices for TCP loss detection RFC5681 and RFC6675. Should be 3 but 10 has a better mitigation for spurious loss detection

		r.sendQueue <- pkt.toBytes()
		r.lastAckSent.Store(ackNo)
		r.lastFrameSent.Store(pkt.frameNo)

		r.unsend = 0
	} else {
		r.unsend++
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

// Retransmission ACKs are extra packets to update the sender/receiver
// on the last ackNo update. It uses the prioritySendQueue.
func (r *Reliable) sendRetransmissionAck(lastFrameNo, ackNo uint32, tubeId byte) {
	rtrPkt := &frame{
		frameNo: lastFrameNo,
		data:    []byte{},
		flags:   frameFlags{RTR: true, ACK: true, REL: true},
		tubeID:  tubeId,
		ackNo:   ackNo,
	}

	r.log.WithFields(logrus.Fields{
		"Frame N°": rtrPkt.frameNo,
		"Ack N°":   ackNo,
	}).Trace("Retransmission of RTR ack")

	// Uses the priority queue to retransmit faster
	r.prioritySendQueue <- rtrPkt.toBytes()
}

// send continuously reads packet from the sends and hands them to the muxer
func (r *Reliable) send() {
	var pkt *frame
	ok := true
	for ok {
		select {
		// onTimeout sender
		case <-r.sender.RetransmitTicker.C: // +checklocksignore accessing channels is safe

			r.l.Lock()

			numFrames := r.sender.framesToSend(true, 0)

			rtoSent := false

			for i := 0; i < numFrames; i++ {
				rtoFrame := &r.sender.frames[i]

				r.log.WithFields(logrus.Fields{
					"Frame N°": rtoFrame.frame.frameNo,
					"Ack N°":   r.recvWindow.getAck(),
				}).Trace("Retransmission RTO")

				// To notify the receiver of a RTO frame

				if common.Debug {
					logrus.Debugf("I send rto n°%v with rto %v", rtoFrame.frameNo, r.sender.RTO)
				}

				rtoFrame.flags.RTR = true
				rtoFrame.Time = time.Now()

				if !rtoFrame.queued && rtoFrame.dataLength > 0 {
					r.sender.unacked++
					rtoFrame.queued = true
				}

				r.sendOneFrame(rtoFrame.frame, true)

				rtoSent = true
			}

			// Back off RTO if no ACKs were received
			r.sender.RTO *= 2

			// Reduce the window size if rto frame sent and no recent congestion event
			if rtoSent && r.sender.senderWindow.state == AIMD {
				r.sender.senderWindow.state = FastRecovery
				newcwndSize := 3 * r.sender.senderWindow.cwndSize / 4 // the traditional 1/2 is too aggressive when considering frame bursts
				r.sender.senderWindow.cwndSize = newcwndSize
				r.sender.senderWindow.windowSize = uint16(newcwndSize)
				r.sender.rtoCounter = 0
			}

			if r.sender.senderWindow.state == FastRecovery {
				r.sender.rtoCounter++
			}

			if rtoSent && r.sender.senderWindow.state == SlowStart {
				newcwndSize := r.sender.senderWindow.cwndSize / 2
				r.sender.senderWindow.ssThresh = uint16(newcwndSize)
				r.sender.senderWindow.cwndSize = newcwndSize
				r.sender.senderWindow.state = FastRecovery // will switch to AIMD on the next successful ack
			}

			if r.sender.RTO > maxRTO && len(r.sender.frames) > 0 {
				logrus.Errorf("REL: RTO exeeded, dropping frame n° %v", r.sender.frames[0].frameNo)
				r.sender.frames = r.sender.frames[1:]
				r.sender.RTO = r.sender.RTT
			}

			r.sender.resetRetransmitTicker()

			r.l.Unlock()

		case <-r.sender.senderWindow.windowOpen: // +checklocksignore accessing channels is safe
			r.l.Lock()
			numFrames := r.sender.framesToSend(false, 0)
			r.log.WithField("numFrames", numFrames).Trace("window open")

			numQueued := 0

			for i := 0; i < len(r.sender.frames) && numQueued < numFrames; i++ {
				windowFrame := &r.sender.frames[i]

				if !windowFrame.queued {
					r.log.WithFields(logrus.Fields{
						"frame No": windowFrame.frame.frameNo,
						"unacked":  r.sender.unacked,
					}).Trace("Window sending")

					windowFrame.Time = time.Now()
					windowFrame.queued = true

					safeSend(r.sender.sendQueue, windowFrame.frame)

					r.sender.unacked++

					numQueued++
				}
			}
			r.l.Unlock()

		case pkt, ok = <-r.sender.sendQueue: // +checklocksignore accessing channels is safe
			if !ok {
				break
			}

			// Do not block ACKs - Blocks frame transmission out of window open
			r.sendOneFrame(pkt, false)
		}
	}
	r.log.Debug("send ended")
	close(r.sendDone)
}

// safeSend prevent to send a frame on a closed channel
func safeSend(ch chan *frame, value *frame) (closed bool) {
	defer func() {
		if recover() != nil {
			closed = true
		}
	}()

	ch <- value
	return false
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

	if pkt.flags.RTR && !pkt.flags.ACK && pkt.dataLength > 0 {
		newAck := r.recvWindow.getAck()
		r.sendRetransmissionAck(pkt.ackNo, newAck, r.id)
		//r.unsend = 0
	}

	finProcessed, err := r.recvWindow.receive(pkt)

	// Pass the frame to the sender
	if pkt.flags.ACK {
		missingFrameNo, _ := r.sender.recvAck(pkt.ackNo)
		if missingFrameNo != 0 {
			r.sender.m.Lock()
			r.sendFrameByNumberLocked(missingFrameNo)
			r.sender.m.Unlock()
		}
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

	err = r.sender.sendFin()

	return err
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

// +checklocks:r.l
func (r *Reliable) sendFrameByNumberLocked(frameNo uint32) {
	if common.Debug {
		logrus.Debugf("Searching for frame %v to priority send it", frameNo)
	}
	if len(r.sender.frames) < defaultWindowSize {
		if common.Debug {
			logrus.Debugf("Frame list has less than %v frames", defaultWindowSize)
		}
		return
	}
	for i := 0; i < defaultWindowSize; i++ {
		rtrFrame := *r.sender.frames[i].frame
		if rtrFrame.frameNo == frameNo && rtrFrame.queued {
			r.sender.frames[i].Time = time.Now()
			r.prioritySendQueue <- rtrFrame.toBytes()
			if common.Debug {
				logrus.Debugf("Frame %v found and prority sent", frameNo)
			}
			return
		} else if rtrFrame.frameNo > frameNo {
			if common.Debug {
				logrus.Debugf("Frame %v not found, frame number in the list are greater than the frameNo", frameNo)
			}
			return
		}
	}
	if common.Debug {
		logrus.Debugf("Frame %v not found in the frame list", frameNo)
	}
}

// CanAcceptBytes is currently called every 10ms to copy data in the frames list
// It can slow down the sender if called more often as locking and unlocking are slow.
func (r *Reliable) CanAcceptBytes() bool {
	r.l.Lock()
	defer r.l.Unlock()
	senderWindowSize := r.sender.getWindowSize()
	return len(r.sender.frames) < int(senderWindowSize)
}
