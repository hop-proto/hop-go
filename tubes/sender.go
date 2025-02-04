package tubes

import (
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
)

type sender struct {
	// The acknowledgement number sent from the other end of the connection.
	ackNo uint64

	frameNo    uint32
	windowSize uint16

	// The number of packets sent but not acked
	unacked uint16

	finSent    bool
	finFrameNo uint32

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

	// RTT is the estimate of the round trip time to the remote host
	RTT             time.Duration
	RTRFrameCounter int

	// the time after which writes will expire
	deadline time.Time

	// signals that more data be sent
	windowOpen chan struct{}

	sendQueue chan *frame

	// logging context
	log *logrus.Entry
}

func newSender(log *logrus.Entry) *sender {
	return &sender{
		ackNo:   1,
		frameNo: 1,
		unacked: 0,
		buffer:  make([]byte, 0),
		// finSent defaults to false
		RetransmitTicker: time.NewTicker(initialRTT),
		RTT:              initialRTT,
		RTRFrameCounter:  initialRTTCounter,
		windowSize:       windowSize,
		windowOpen:       make(chan struct{}, 1),
		sendQueue:        make(chan *frame, 1024), // TODO(hosono) make this size 0
		log:              log.WithField("sender", ""),
	}
}

func (s *sender) unAckedFramesRemaining() int {
	return len(s.frames)
}

// Reset the retransmission timer to 9/8 of the measured RTT
// 9/8 comes from RFC 9002 section 6.1.2
func (s *sender) resetRetransmitTicker() {
	s.RetransmitTicker.Reset((s.RTT / 8) * 9)
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
		s.frames = append(s.frames, struct {
			*frame
			time.Time
		}{&pkt, time.Time{}})
	}

	numFrames := s.framesToSend(false, startFrame)

	for i := 0; i < numFrames; i++ {
		pkt := s.frames[startFrame+i]
		s.unacked++
		s.frames[startFrame+i].Time = time.Now()
		s.frames[startFrame+i].queued = true
		s.sendQueue <- pkt.frame
	}

	s.resetRetransmitTicker()
	return len(b), nil
}

func (s *sender) recvAck(ackNo uint32) error {
	// Stop the ticker since we're about to do a new RTT measurement.
	s.RetransmitTicker.Stop()

	oldAckNo := s.ackNo
	newAckNo := uint64(ackNo)
	if newAckNo < s.ackNo && (newAckNo+(1<<32)-s.ackNo <= uint64(s.windowSize)) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	windowOpen := s.ackNo < newAckNo

	//logrus.Debugf("I received the ack, %v", ackNo)

	for s.ackNo < newAckNo {
		if !s.frames[0].Time.Equal(time.Time{}) && ackNo == s.frames[0].frame.frameNo+1 {
			oldRTT := s.RTT
			measuredRTT := time.Since(s.frames[0].Time)

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
		s.ackNo++
		s.RTRFrameCounter = initialRTTCounter
		// to not block the retransmission if concurrency
		//s.frames[0].queued = false
		s.frames = s.frames[1:]
		if s.unacked > 0 {
			s.unacked--
		}

		s.log.WithFields(logrus.Fields{
			"ack frame No": newAckNo,
			"unacked":      s.unacked,
			"new ack now":  s.ackNo,
		}).Trace("I am acknowledging")

		//logrus.Debugf("I am acknowledging the ack, %v, and I have unacked: %v, and my new ack now is : %v", newAckNo, s.unacked, s.ackNo)
	}

	if common.Debug {
		s.log.WithFields(logrus.Fields{
			"old ackNo": oldAckNo,
			"new ackNo": newAckNo,
		}).Trace("updated ackNo")
	}

	// Only fill the window if new space has really opened up
	if windowOpen {
		select {
		case s.windowOpen <- struct{}{}:
			//logrus.Debugf("I break the window on ack now, %v", newAckNo)
			break
		default:
			break
		}
	}

	s.resetRetransmitTicker()

	return nil
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
		numFrames = s.RTRFrameCounter

		if numFrames > maxFragTransPerRTO {
			numFrames = maxFragTransPerRTO
		}
	} else {
		numFrames = int(s.windowSize) - int(s.unacked) - startIndex
	}

	// Clamp value to avoid going out of bounds
	if numFrames+startIndex > len(s.frames) {
		numFrames = len(s.frames) - startIndex
	}
	if numFrames < 0 {
		numFrames = 0
	}
	//logrus.Debugf("len s.frames %v", len(s.frames))
	return numFrames
}

// Close stops the sender and causes future writes to return io.EOF
func (s *sender) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		close(s.sendQueue)

		return nil
	}
	return io.EOF
}

func (s *sender) sendFin() error {
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
	s.frames = append(s.frames, struct {
		*frame
		time.Time
	}{&pkt, time.Time{}})
	s.sendQueue <- &pkt
	s.unacked++
	return nil
}
