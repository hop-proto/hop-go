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
	// +checklocksignore
	sender     *sender
	recvWindow *receiver
	// outbound is owned by the Muxer. Reliable never accesses or closes its raw
	// queues; every handoff is cancellation-aware.
	outbound *outbox
	// +checklocks:l
	tubeState state
	// +checklocks:l
	lastAckTimer  *time.Timer
	lastAckSent   atomic.Uint32 // +checklocksignore
	lastFrameSent atomic.Uint32 // +checklocksignore
	// +checklocks:l
	unsend uint16

	// closed publishes completion of the lifecycle transition and sender drain.
	closed chan struct{}
	// closeRequested is independently publishable and wakes initiation without
	// acquiring l. Normal FIN processing continues until terminal close.
	closeRequested     chan struct{}
	closeRequestedOnce sync.Once
	// +checklocks:l
	closeStarted bool
	// initRecv publishes receipt of the peer's initiation frame.
	initRecv chan struct{}
	// initDone publishes termination of the initiation producer.
	initDone chan struct{}
	// sendDone publishes that all locally prepared sender frames were handed to the Muxer.
	// It does not mean that the Muxer wrote those frames to the transport.
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
		defer ticker.Stop()
	initLoop:
		for {
			r.l.Lock()
			state := r.tubeState
			r.l.Unlock()
			if state == initiated {
				break initLoop
			}
			if state != created {
				return
			}

			if err := r.outbound.enqueue(outboundFrame{bytes: p.toBytes()}, r.closeRequested); err != nil {
				if !errors.Is(err, io.EOF) {
					r.closeFromOutboundFailure()
				}
				return
			}

			select {
			case <-ticker.C:
				r.log.Info("init rto exceeded")
			case <-r.initRecv:
			case <-r.closeRequested:
				r.l.Lock()
				initiatedNow := r.tubeState == initiated
				r.l.Unlock()
				if initiatedNow {
					break initLoop
				}
				return
			}
		}
	} else {
		select {
		case <-r.initRecv:
		case <-r.closeRequested:
			return
		}
	}

	r.l.Lock()
	if r.tubeState != initiated {
		r.l.Unlock()
		return
	}
	r.sender.closed.Store(false)
	go r.send()
	r.l.Unlock()
}

// +checklocks:r.l
func (r *Reliable) prepareFrameLocked(pkt *frame, retransmission bool) (outboundFrame, bool) {
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

		r.lastAckSent.Store(ackNo)
		r.lastFrameSent.Store(pkt.frameNo)

		r.unsend = 0
		return outboundFrame{bytes: pkt.toBytes(), priority: retransmission}, true
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
		}).Trace("prepared packet for muxer admission")
	}
	return outboundFrame{}, false
}

// Retransmission ACKs are extra packets to update the sender/receiver
// on the last ackNo update.
// +checklocks:r.l
func (r *Reliable) retransmissionAckLocked(lastFrameNo, ackNo uint32, tubeId byte) (outboundFrame, bool) {
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

	return r.prepareFrameLocked(rtrPkt, true)
}

// send selects new data and retransmissions, then releases the lifecycle lock
// before asking the Muxer outbox to admit them.
func (r *Reliable) send() {
	defer func() {
		r.log.Debug("send ended")
		close(r.sendDone)
	}()

	for {
		select {
		case <-r.sender.done:
			return
		case <-r.sender.RetransmitTicker.C:

			r.l.Lock()
			if r.sender.closed.Load() {
				r.l.Unlock()
				return
			}

			numFrames := r.sender.framesToSend(true, 0)
			rtoSent := false
			outbound := make([]outboundFrame, 0, numFrames)

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

				if frame, ok := r.prepareFrameLocked(rtoFrame.frame, true); ok {
					outbound = append(outbound, frame)
				}

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
			if err := r.admitOutbound(outbound, r.sender.done); err != nil {
				if !errors.Is(err, io.EOF) {
					r.closeFromOutboundFailure()
				}
				return
			}

		case <-r.sender.senderWindow.windowOpen:
			r.l.Lock()
			if r.sender.closed.Load() {
				r.l.Unlock()
				return
			}
			numFrames := r.sender.framesToSend(false, 0)
			r.log.WithField("numFrames", numFrames).Trace("window open")

			numQueued := 0
			outbound := make([]outboundFrame, 0, numFrames)

			for i := 0; i < len(r.sender.frames) && numQueued < numFrames; i++ {
				windowFrame := &r.sender.frames[i]

				if !windowFrame.queued {
					r.log.WithFields(logrus.Fields{
						"frame No": windowFrame.frame.frameNo,
						"unacked":  r.sender.unacked,
					}).Trace("Window sending")

					windowFrame.Time = time.Now()
					windowFrame.queued = true
					r.sender.unacked++
					if frame, ok := r.prepareFrameLocked(windowFrame.frame, false); ok {
						outbound = append(outbound, frame)
					}

					numQueued++
				}
			}
			r.l.Unlock()
			if err := r.admitOutbound(outbound, r.sender.done); err != nil {
				if !errors.Is(err, io.EOF) {
					r.closeFromOutboundFailure()
				}
				return
			}
		}
	}
}

func (r *Reliable) admitOutbound(frames []outboundFrame, canceled <-chan struct{}) error {
	for _, frame := range frames {
		if err := r.outbound.enqueue(frame, canceled); err != nil {
			return err
		}
	}
	return nil
}

func (r *Reliable) closeFromOutboundFailure() {
	go func() {
		r.l.Lock()
		defer r.l.Unlock()
		r.enterClosedState()
	}()
}

// receive is called by the muxer for each new packet
//
//nolint:gocyclo // The reliable protocol state machine is intentionally centralized here.
func (r *Reliable) receive(pkt *frame) error {
	r.l.Lock()

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
		r.l.Unlock()
		return ErrBadTubeState
	}
	outbound := make([]outboundFrame, 0, 3)
	closeAfterAdmission := false

	if pkt.flags.RTR && !pkt.flags.ACK && pkt.dataLength > 0 {
		newAck := r.recvWindow.getAck()
		if frame, ok := r.retransmissionAckLocked(pkt.ackNo, newAck, r.id); ok {
			outbound = append(outbound, frame)
		}
	}

	finProcessed, err := r.recvWindow.receive(pkt)

	// Pass the frame to the sender
	if pkt.flags.ACK {
		missingFrameNo, ackErr := r.sender.recvAck(pkt.ackNo)
		if ackErr != nil {
			r.enterClosedState()
			r.l.Unlock()
			return ackErr
		}
		if missingFrameNo != 0 {
			r.sender.m.Lock()
			missing := r.frameByNumberLocked(missingFrameNo)
			r.sender.m.Unlock()
			if missing != nil {
				if frame, ok := r.prepareFrameLocked(missing, true); ok {
					outbound = append(outbound, frame)
				}
			}
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
			closeAfterAdmission = true
		case lastAck:
			r.log.Debug("got ACK of FIN packet. going from lastAck to closed")
			closeAfterAdmission = true
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
			if ack := r.sender.emptyPacket(); ack != nil {
				if frame, ok := r.prepareFrameLocked(ack, false); ok {
					outbound = append(outbound, frame)
				}
			}
			closeAfterAdmission = true
		}
		if !closeAfterAdmission {
			r.log.Trace("sending ACK of FIN")
			if ack := r.sender.emptyPacket(); ack != nil {
				if frame, ok := r.prepareFrameLocked(ack, false); ok {
					outbound = append(outbound, frame)
				}
			}
		}
	}

	// ACK every data packet
	if pkt.dataLength > 0 && !closeAfterAdmission && !pkt.flags.FIN {
		if ack := r.sender.emptyPacket(); ack != nil {
			if frame, ok := r.prepareFrameLocked(ack, false); ok {
				outbound = append(outbound, frame)
			}
		}
	}

	if closeAfterAdmission {
		r.enterClosedStateWithFrames(outbound)
		r.l.Unlock()
		return err
	}
	r.l.Unlock()

	if admitErr := r.admitOutbound(outbound, r.sender.done); admitErr != nil && !errors.Is(admitErr, io.EOF) {
		r.closeFromOutboundFailure()
		return admitErr
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
	r.enterClosedStateWithFrames(nil)
}

// enterClosedStateWithFrames begins terminal shutdown while locked, releases
// the lifecycle lock for reserved final-frame admission and sender completion,
// then publishes close completion. Reserved frames (notably the final FIN ACK)
// are admitted before sender cancellation can discard them.
// +checklocks:r.l
func (r *Reliable) enterClosedStateWithFrames(frames []outboundFrame) {
	if r.closeStarted {
		return
	}
	r.closeStarted = true
	r.tubeState = closed
	if r.closeRequested != nil {
		r.closeRequestedOnce.Do(func() {
			close(r.closeRequested)
		})
	}
	if r.lastAckTimer != nil {
		r.lastAckTimer.Stop()
	}
	waitForSender := r.sender.Close() == nil
	r.recvWindow.Close()
	r.l.Unlock()
	if len(frames) > 0 && r.outbound != nil {
		_ = r.admitOutbound(frames, nil)
	}
	if waitForSender {
		<-r.sendDone
	}
	r.l.Lock()
	close(r.closed)
}

func (r *Reliable) receiveInitiatePkt(pkt *initiateFrame) error {
	r.l.Lock()

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
		if _, err := r.sender.recvAck(1); err != nil {
			r.enterClosedState()
			r.l.Unlock()
			return err
		}
		close(r.initRecv)
	}

	var response []byte
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
		response = p.toBytes()
	}
	r.l.Unlock()

	if response != nil {
		if err := r.outbound.enqueue(outboundFrame{bytes: response}, r.closeRequested); err != nil {
			if !errors.Is(err, io.EOF) {
				r.closeFromOutboundFailure()
			}
			return err
		}
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

// Write queues b in the Reliable sender. It can return before the frame is
// handed to the Muxer or written to the underlying transport.
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

// Close initiates the Reliable FIN state machine after admitting the FIN to the
// local sender. It does not wait for sender drain or peer acknowledgement; use
// WaitForClose for lifecycle completion.
func (r *Reliable) Close() (err error) {
	if r.closeRequested != nil {
		r.closeRequestedOnce.Do(func() {
			close(r.closeRequested)
		})
	}
	<-r.initDone

	r.l.Lock()

	switch r.tubeState {
	case created:
		r.log.WithField("state", r.tubeState).Warn("tried to close tube in bad state")
		r.enterClosedState()
		r.l.Unlock()
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
		r.l.Unlock()
		return io.EOF
	}

	// Cancel all pending read and write operations
	r.recvWindow.dataReady.SetDeadline(time.Now())
	r.sender.deadline = time.Now()

	err = r.sender.sendFin()
	r.l.Unlock()

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
func (r *Reliable) frameByNumberLocked(frameNo uint32) *frame {
	if common.Debug {
		logrus.Debugf("Searching for frame %v to priority send it", frameNo)
	}
	if len(r.sender.frames) < defaultWindowSize {
		if common.Debug {
			logrus.Debugf("Frame list has less than %v frames", defaultWindowSize)
		}
		return nil
	}
	for i := 0; i < defaultWindowSize; i++ {
		rtrFrameStruct := &r.sender.frames[i]
		if rtrFrameStruct.frameNo == frameNo && rtrFrameStruct.queued {
			rtrFrameStruct.Time = time.Now()
			if common.Debug {
				logrus.Debugf("Frame %v found and prority sent", frameNo)
			}
			return rtrFrameStruct.frame
		} else if rtrFrameStruct.frameNo > frameNo {
			if common.Debug {
				logrus.Debugf("Frame %v not found, frame number in the list are greater than the frameNo", frameNo)
			}
			return nil
		}
	}
	if common.Debug {
		logrus.Debugf("Frame %v not found in the frame list", frameNo)
	}
	return nil
}

// CanAcceptBytes is currently called every 10ms to copy data in the frames list
// It can slow down the sender if called more often as locking and unlocking are slow.
func (r *Reliable) CanAcceptBytes() bool {
	r.l.Lock()
	defer r.l.Unlock()
	senderWindowSize := r.sender.getWindowSize()
	return len(r.sender.frames) < int(senderWindowSize)
}
