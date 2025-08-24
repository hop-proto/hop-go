package tubes

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
)

type sender struct {
	// The acknowledgement number sent from the other end of the connection.
	// +checklocks:m
	ackNo uint64

	frameNo uint32

	// The number of packets sent but not acked
	unacked    uint16
	rtoCounter int

	senderWindow senderWindow

	finSent    bool
	finFrameNo uint32 // +checklocksignore

	closed atomic.Bool

	// The buffer of unacknowledged tube frames that will be retransmitted if necessary
	// along with the time when they were sent
	frames []struct {
		*frame
		time.Time
	}

	// The current buffer of unacknowledged bytes from the sender.
	// A byte slice works well here because:
	// 	(1) we need to accommodate resending fragments of potentially varying window sizes
	// 	based on the receiving end, so being able to arbitrarily index from the front is important.
	//	(2) the append() function when write() is called will periodically clean up the unused
	//	memory in the front of the slice by reallocating the buffer array.
	// TODO(hosono) ideally, we would have a maximum buffer size beyond with reads would block
	buffer []byte

	// Retransmission TimeOut.
	RetransmitTicker *time.Ticker

	// RTO is the Recovery Time Objective, which aims to be used only on two consecutive packet loss
	RTO time.Duration

	// RTT is the estimate of the round trip time to the remote host
	RTT time.Duration

	// the time after which writes will expire
	deadline time.Time

	sendQueue         chan *frame
	prioritySendQueue chan *frame

	m sync.Mutex

	// logging context
	log *logrus.Entry
}
type controlState int

const (
	SlowStart controlState = iota
	AIMD
	FastRecovery
)

type senderWindow struct {
	state                controlState
	cwndSize             float64
	duplicatedAckCounter int
	ssThresh             uint16 // SSTHRESH helps the congestion control algorithm remember the latest safe rate.
	windowSize           uint16

	// signals that more data be sent
	windowOpen chan struct{}
}

func newSender(log *logrus.Entry) *sender {
	return &sender{
		ackNo:      1,
		frameNo:    1,
		unacked:    0,
		rtoCounter: 0,
		buffer:     make([]byte, 0),
		// finSent defaults to false
		RetransmitTicker: time.NewTicker(initialRTT),
		RTT:              initialRTT,
		RTO:              initialRTT,
		senderWindow: senderWindow{
			state:                SlowStart,
			cwndSize:             defaultWindowSize,
			duplicatedAckCounter: 0,
			ssThresh:             512,
			windowSize:           defaultWindowSize,
			windowOpen:           make(chan struct{}, 1),
		},
		sendQueue:         make(chan *frame, 1024), // TODO(hosono) make this size 0
		prioritySendQueue: make(chan *frame, 1024),
		log:               log.WithField("sender", ""),
	}
}

func (s *sender) unAckedFramesRemaining() int {
	s.m.Lock()
	defer s.m.Unlock()
	return len(s.frames)
}

// Reset the retransmission timer to 9/8 of the measured RTT
// 9/8 comes from RFC 9002 section 6.1.2
func (s *sender) resetRetransmitTicker() {
	s.RetransmitTicker.Reset((s.RTO / 8) * 9)
}

func (s *sender) write(b []byte) (int, error) {
	if !s.deadline.IsZero() && time.Now().After(s.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if s.finSent || s.closed.Load() {
		return 0, io.EOF
	}
	s.buffer = append(s.buffer, b...)

	startFrame := len(s.frames)

	for len(s.buffer) > 0 {
		dataLength := MaxFrameDataLength
		if len(s.buffer) < int(dataLength) {
			dataLength = uint16(len(s.buffer))
		}
		pkt := frame{
			dataLength: dataLength,
			frameNo:    s.frameNo,
			data:       s.buffer[:dataLength],
			queued:     false,
		}

		s.frameNo++
		s.buffer = s.buffer[dataLength:]
		s.m.Lock()
		s.frames = append(s.frames, struct {
			*frame
			time.Time
		}{&pkt, time.Time{}})
		s.m.Unlock()
	}

	numFrames := s.framesToSend(false, startFrame)

	if numFrames > 0 {
		select {
		case s.senderWindow.windowOpen <- struct{}{}:
			break
		default:
			break
		}
	}

	return len(b), nil
}

func (s *sender) recvAck(ackNo uint32) (uint32, error) {
	s.m.Lock()
	defer s.m.Unlock()

	// Stop the ticker since we're about to do a new RTT measurement.
	s.RetransmitTicker.Stop()

	missingFrameNo := uint32(0)
	oldAckNo := s.ackNo
	newAckNo := uint64(ackNo)
	if newAckNo < s.ackNo && (newAckNo+(1<<32)-s.ackNo <= uint64(s.senderWindow.windowSize)) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	if s.senderWindow.duplicatedAckCounter > 100 {
		// TODO (paul): make sure that this is the right way to terminate a connection
		// Should not happen
		s.Close()
	}

	// to not apply on the first 20 ACKs as the network probing is inaccurate
	if oldAckNo == newAckNo && newAckNo > 20 {
		missingFrameNo = s.onLoss(ackNo)
	}

	windowOpen := s.ackNo < newAckNo

	if s.senderWindow.state == FastRecovery && oldAckNo == newAckNo {
		windowOpen = true
	}

	for s.ackNo < newAckNo {
		s.onSuccess(ackNo)
		s.ackNo++
		s.frames = s.frames[1:]
		if s.unacked > 0 {
			s.unacked--
		}
	}

	if common.Debug {
		s.log.WithFields(logrus.Fields{
			"old ackNo": oldAckNo,
			"new ackNo": newAckNo,
		}).Trace("updated ackNo")
	}

	// Limite window size lower value
	if s.senderWindow.cwndSize < 10 {
		s.senderWindow.cwndSize = 10
	}

	// update the windowsize from the cwndSize
	s.senderWindow.windowSize = uint16(s.senderWindow.cwndSize)

	if common.Debug {
		logrus.Debugf("windowsSize %v", s.senderWindow.windowSize)
	}

	// Only fill the window if new space has really opened up
	if windowOpen {
		select {
		case s.senderWindow.windowOpen <- struct{}{}:
			break
		default:
			break
		}
	}

	s.resetRetransmitTicker()

	return missingFrameNo, nil
}

func (s *sender) onSuccess(ackNo uint32) {

	if !s.frames[0].Time.Equal(time.Time{}) && ackNo == s.frames[0].frame.frameNo+1 && !s.frames[0].flags.RTR {
		oldRTT := s.RTT
		measuredRTT := time.Since(s.frames[0].Time)

		// RTT Upper bound
		measuredRTT = min(measuredRTT, s.RTT*2)

		// This formula comes from RFC 9002 section 5.3
		s.RTT = (s.RTT/8)*7 + measuredRTT/8

		if s.RTT < minRTT {
			s.RTT = minRTT
		}

		if common.Debug {
			s.log.WithFields(logrus.Fields{
				"oldRTT":      oldRTT,
				"measuredRTT": measuredRTT,
				"newRTT":      s.RTT,
			}).Trace("updated rtt")
		}
	}

	if s.frames[0].dataLength > 1000 {

		// Each time we receive an acknowledgement, we will take the current window size CWND and reassign it to CWND + (1/CWND)
		if s.senderWindow.state == AIMD {
			s.senderWindow.cwndSize = s.senderWindow.cwndSize + (1 / s.senderWindow.cwndSize) // +=CWND + (1/CWND)

		} else { // Slow start or recovery
			s.senderWindow.cwndSize++

			// Slow start is used when congestion window is no greater than the slow start
			// threshold
			if uint16(s.senderWindow.cwndSize) > s.senderWindow.ssThresh {
				s.senderWindow.state = AIMD
			}
		}

	}

	s.senderWindow.duplicatedAckCounter = 0

	// Adjust the RTO on the RTT when receive an ACK
	s.RTO = (s.RTT / 8) * 9
}

func (s *sender) onLoss(ackNo uint32) uint32 {

	missingFrameNo := uint32(0)

	s.senderWindow.duplicatedAckCounter++

	// Missing frames on second duplicate ACK
	// Proactively retransmits subsequent frames on > 1 duplicate ACKs

	if s.senderWindow.duplicatedAckCounter < 5 {
		missingFrameNo = ackNo + uint32(s.senderWindow.duplicatedAckCounter) - 1 // congestion on the path -> retransmit before cutting the window
		if s.senderWindow.state == FastRecovery {
			if s.senderWindow.duplicatedAckCounter == 1 {
				missingFrameNo = 0 // don't send on first frame
			} else {
				missingFrameNo -= 1 // increment the index from dup ack = 2
			}
		}
	} else {
		missingFrameNo = ackNo
	}

	if common.Debug {
		logrus.Debugf("I received the ack %v, n %v times, windowS %v, ssThresh %v", ackNo, s.senderWindow.duplicatedAckCounter, s.senderWindow.windowSize, s.senderWindow.ssThresh)
	}

	if s.senderWindow.state == AIMD && s.senderWindow.duplicatedAckCounter == 2 {
		// clamp the lower value of the ssThresh
		newAIMDcwndSize := (3 * s.senderWindow.cwndSize) / 4

		s.senderWindow.ssThresh = uint16(newAIMDcwndSize)
		s.senderWindow.cwndSize = newAIMDcwndSize

	} else if s.senderWindow.state == SlowStart {
		newcwndSize := s.senderWindow.cwndSize / 2
		s.senderWindow.ssThresh = uint16(newcwndSize)
		s.senderWindow.cwndSize = newcwndSize
		s.senderWindow.state = FastRecovery // will switch to AIMD on the next successful ack
	}

	// clamp the lower value of the minimum value 10
	if s.senderWindow.cwndSize < minWindowSize {
		s.senderWindow.cwndSize = minWindowSize
	}

	return missingFrameNo
}

func (s *sender) sendEmptyPacket() {
	if s.closed.Load() {
		return
	}
	pkt := &frame{
		dataLength: 0,
		frameNo:    s.frameNo,
		data:       []byte{},
	}
	s.sendQueue <- pkt
}

func (s *sender) framesToSend(rto bool, startIndex int) int {
	// TODO(hosono) this is a mess because there's no builtin min or clamp functions
	var numFrames int
	if rto {
		if s.rtoCounter < int(s.senderWindow.windowSize) {
			numFrames = s.rtoCounter + 1
		} else {
			numFrames = int(s.senderWindow.windowSize)
		}
	} else {
		numFrames = int(s.senderWindow.windowSize) - int(s.unacked) - startIndex
	}

	// Clamp value to avoid going out of bounds
	if numFrames+startIndex > len(s.frames) {
		numFrames = len(s.frames) - startIndex
	}
	if numFrames < 0 {
		numFrames = 0
	}
	return numFrames
}

// Close stops the sender and causes future writes to return io.EOF
func (s *sender) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		close(s.sendQueue)
		close(s.prioritySendQueue)

		return nil
	}
	return io.EOF
}

func (s *sender) sendFin() error {
	s.m.Lock()
	defer s.m.Unlock()

	if s.finSent {
		return io.EOF
	}
	s.finSent = true

	pkt := frame{
		dataLength: 0,
		frameNo:    s.frameNo,
		data:       []byte{},
		queued:     false,
		flags: frameFlags{
			ACK:  true,
			FIN:  true,
			REQ:  false,
			RESP: false,
		},
	}
	s.finFrameNo = pkt.frameNo
	s.log.WithField("frameNo", pkt.frameNo).Debug("queueing FIN packet")

	s.frameNo++

	// To properly close the receiver
	addToSendQueue := false

	if len(s.frames) == 0 {
		pkt.queued = true
		s.unacked++
		addToSendQueue = true
	}

	s.frames = append(s.frames, struct {
		*frame
		time.Time
	}{&pkt, time.Time{}})

	if addToSendQueue {
		s.sendQueue <- &pkt
	}

	return nil
}

func (s *sender) getWindowSize() uint16 {
	s.m.Lock()
	defer s.m.Unlock()
	return s.senderWindow.windowSize
}
