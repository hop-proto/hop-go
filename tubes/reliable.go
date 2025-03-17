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
	sender            *sender
	recvWindow        *receiver
	sendQueue         chan []byte
	prioritySendQueue chan []byte
	// +checklocks:l
	tubeState state
	// +checklocks:l
	lastAckTimer     *time.Timer
	lastAckSent      atomic.Uint32
	lastFrameSent    atomic.Uint32
	lastRTRSent      atomic.Uint32
	pendingRTRTimers sync.Map
	closed           chan struct{}
	initRecv         chan struct{}
	initDone         chan struct{}
	sendDone         chan struct{}
	l                sync.Mutex
	log              *logrus.Entry
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

	missingFrame := r.recvWindow.missingFrame.Load()

	if missingFrame && lastAckNo != ackNo {
		frameToSendCounter := r.recvWindow.getFrameToSendCounter()
		r.sendRetransmissionAck(lastFrameNo, ackNo, frameToSendCounter)
		r.recvWindow.missingFrame.Store(false)
		r.lastAckSent.Store(ackNo)
	}

	// Limit the retransmission of ACKs to the last value loaded through r.recvWindow.getAck()
	if pkt.dataLength > 0 ||
		(pkt.dataLength == 0 && (ackNo != lastAckNo || pkt.frameNo != lastFrameNo ||
			retransmission || pkt.flags.FIN || pkt.flags.RESP)) {

		r.sendQueue <- pkt.toBytes()
		r.lastAckSent.Store(ackNo)
		r.lastFrameSent.Store(pkt.frameNo)
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

func (r *Reliable) sendRetransmissionAck(lastFrameNo, ackNo uint32, frameToSendCounter uint16) {
	rtrPkt := &frame{
		dataLength: frameToSendCounter,
		frameNo:    lastFrameNo,
		data:       []byte{},
		flags:      frameFlags{RTR: true, ACK: true, REL: true},
		tubeID:     r.id,
		ackNo:      ackNo,
	}

	r.log.WithFields(logrus.Fields{
		"Frame N°": rtrPkt.frameNo,
		"Ack N°":   ackNo,
	}).Trace("Retransmission of RTR ack")

	// To send before ACKs
	r.prioritySendQueue <- rtrPkt.toBytes()
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

			numFrames := r.sender.framesToSend(true, 0)

			for i := 0; i < numFrames; i++ {
				rtoFrame := &r.sender.frames[i]

				r.log.WithFields(logrus.Fields{
					"Frame N°": rtoFrame.frame.frameNo,
					"Ack N°":   r.recvWindow.getAck(),
				}).Trace("Retransmission RTO")

				// To notify the receiver of a RTO frame

				if common.Debug {
					logrus.Debugf("I send rto with rto %v", r.sender.RTO)
				}

				rtoFrame.flags.RTR = true
				rtoFrame.Time = time.Now()

				if !rtoFrame.queued && rtoFrame.dataLength > 0 {
					r.sender.unacked++
					rtoFrame.queued = true
				}

				r.lastRTRSent.Store(rtoFrame.frameNo)

				r.sendOneFrame(rtoFrame.frame, true)
			}

			// Back off RTO if no ACKs were received
			r.sender.RTO *= 2

			if r.sender.RTO > maxRTO && len(r.sender.frames) > 0 {
				logrus.Errorf("REL: RTO exeeded, dropping frame n°%v", r.sender.frames[0])
				r.sender.frames = r.sender.frames[1:]
				r.sender.RTO = r.sender.RTT
			}

			r.sender.resetRetransmitTicker()

			r.l.Unlock()

		case <-r.sender.windowOpen:
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

		case pkt, ok = <-r.sender.sendQueue:
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

	if pkt.flags.RTR {
		r.receiveRTRFrame(pkt)
	}

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

// An RTR frame is a frame that need to be processed in priority.
// The flag RTR mention to the receiver that a frame is lost due to congestion
// Or packet loss.
func (r *Reliable) receiveRTRFrame(frame *frame) {
	lastSentRTRNo := r.lastRTRSent.Load()
	ackNo := frame.ackNo

	if !frame.flags.ACK && frame.dataLength > 0 {
		frameCounter := r.recvWindow.getFrameToSendCounter()
		newAck := r.recvWindow.getAck()
		r.sendRetransmissionAck(frame.ackNo, newAck, frameCounter)

	}

	if ackNo > lastSentRTRNo {

		// Frames sent via RTO ask the receiver to send a RTR frame
		// with the current processing index

		// To limit the search in a reasonable range
		numFrames := min(windowSize, len(r.sender.frames))

		for i := 0; i < numFrames; i++ {
			rtrFrame := &r.sender.frames[i]

			if rtrFrame.frameNo > ackNo {
				if common.Debug {
					r.log.Debugf("receiver: RTR frame not found in valid range, i=%v", i)
				}
				break
			}

			if rtrFrame.frameNo == ackNo {
				timeSinceQueued := time.Since(rtrFrame.Time)
				r.scheduleRetransmission(rtrFrame.frame, frame.dataLength, timeSinceQueued, i)
				break
			}
		}
	}
}

// scheduleRetransmission manages retransmission with a delay based on RTT
func (r *Reliable) scheduleRetransmission(rtrFrame *frame, dataLength uint16, timeSinceQueued time.Duration, oldFrameIndex int) {

	waitTime := r.sender.RTT - timeSinceQueued

	// Defining an upper bound to be more compliant with retransmission
	if waitTime > r.sender.RTT/2 {
		waitTime = r.sender.RTT / 2
	}

	r.pendingRTRTimers.Range(func(key, value interface{}) bool {
		if timer, valid := value.(*time.Timer); valid {
			timer.Stop()
			if common.Debug {
				r.log.Debugf("Canceled previous retransmission for frame %v", key)
			}
		}
		r.pendingRTRTimers.Delete(key)
		return true
	})

	if waitTime > 0 {
		if common.Debug {
			r.log.Debugf("Scheduling retransmission for frame %d in %v", rtrFrame.frameNo, waitTime)
		}

		// To send an RTO only after the RTR
		r.sender.resetRetransmitTicker()

		timer := time.AfterFunc(waitTime, func() {
			r.executeRetransmission(rtrFrame, dataLength, oldFrameIndex)
		})

		r.pendingRTRTimers.Store(rtrFrame.frameNo, timer)
	} else {
		// If RTT has passed, retransmit immediately
		r.executeRetransmission(rtrFrame, dataLength, oldFrameIndex)
	}
}

// executeRetransmission actually sends the retransmission if no newer frame has arrived.
func (r *Reliable) executeRetransmission(rtrFrame *frame, dataLength uint16, oldFrameIndex int) {
	if r.lastRTRSent.Load() >= rtrFrame.frameNo {
		if common.Debug {
			r.log.Debugf("Skipping retransmission for frame %d, newer frame received", rtrFrame.frameNo)
		}
		r.pendingRTRTimers.Delete(rtrFrame.frameNo)
		return
	}

	if common.Debug {
		r.log.Debugf("Executing retransmission for frame %d", rtrFrame.frameNo)
	}

	frameListLen := r.sender.unAckedFramesRemaining()

	if frameListLen == 0 {
		r.log.Errorf("Sender frames are empty, aborting retransmission for frame %d", rtrFrame.frameNo)
		return
	}

	if oldFrameIndex < 0 || oldFrameIndex+int(dataLength) > frameListLen {
		r.log.Errorf("Invalid retransmission range for frame %d, aborting", rtrFrame.frameNo)
		return
	}
	for j := 0; j < int(dataLength); j++ {
		frameIndex := oldFrameIndex + j

		rtrFullFrame := &r.sender.frames[frameIndex]

		rtrFullFrame.ackNo = r.recvWindow.getAck()
		rtrFullFrame.Time = time.Now()
		rtrFullFrame.flags.REL = true

		if common.Debug {
			r.log.Debugf("Retransmitting frame %d", rtrFullFrame.frameNo)
		}
		r.sender.log.WithFields(logrus.Fields{
			"Frame N°": rtrFullFrame.frameNo,
		}).Trace("Retransmission of RTR pkt")

		r.prioritySendQueue <- rtrFullFrame.toBytes()

		r.lastRTRSent.Store(rtrFullFrame.frameNo)
	}

	r.pendingRTRTimers.Delete(rtrFrame.frameNo)
}
