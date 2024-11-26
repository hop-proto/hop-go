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
	// The buffer of unacknowledged tube frames that will be retransmitted if necessary.
	frames []*frame

	// The current buffer of unacknowledged bytes from the sender.
	// A byte slice works well here because:
	// 	(1) we need to accommodate resending fragments of potentially varying window sizes
	// 	based on the receiving end, so being able to arbitrarily index from the front is important.
	//	(2) the append() function when write() is called will periodically clean up the unused
	//	memory in the front of the slice by reallocating the buffer array.
	// TODO(hosono) ideally, we would have a maximum buffer size beyond with reads would block
	buffer []byte

	// Retransmission TimeOut.
	RTOTicker *time.Ticker

	RTO time.Duration

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
		buffer:  make([]byte, 0),
		// finSent defaults to false
		RTOTicker:  time.NewTicker(retransmitOffset),
		RTO:        retransmitOffset,
		windowSize: windowSize,
		windowOpen: make(chan struct{}, 1),
		sendQueue:  make(chan *frame, 1024), // TODO(hosono) make this size 0
		log:        log.WithField("sender", ""),
	}
}

func (s *sender) unAckedFramesRemaining() int {
	return len(s.frames)
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
		}

		s.frameNo++
		s.buffer = s.buffer[dataLength:]
		s.frames = append(s.frames, &pkt)
	}

	s.fillWindow(false, startFrame)

	s.RTOTicker.Reset(s.RTO)
	return len(b), nil
}

func (s *sender) recvAck(ackNo uint32) error {
	oldAckNo := s.ackNo
	newAckNo := uint64(ackNo)
	if newAckNo < s.ackNo && (newAckNo+(1<<32)-s.ackNo <= uint64(s.windowSize)) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	windowOpen := s.ackNo < newAckNo

	for s.ackNo < newAckNo {
		s.ackNo++
		s.unacked--
		s.frames = s.frames[1:]
	}

	if common.Debug {
		s.log.WithFields(logrus.Fields{
			"old ackNo": oldAckNo,
			"new ackNo": newAckNo,
		}).Trace("updated ackNo")
	}

	// Only fill the window if new space has really opened up
	if windowOpen {
		s.RTOTicker.Reset(s.RTO)
		select {
		case s.windowOpen <- struct{}{}:
			break
		default:
			break
		}
	}

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
		// Get the minimum of s.windowSize and maxFragTransPerRTO
		if maxFragTransPerRTO > int(s.windowSize) {
			numFrames = int(s.windowSize)
		} else {
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
	return numFrames
}

// rto is true if the window is filled due to a retransmission timeout and false otherwise
func (s *sender) fillWindow(rto bool, startIndex int) {
	numFrames := s.framesToSend(rto, startIndex)

	for i := 0; i < numFrames; i++ {
		pkt := s.frames[startIndex+i]
		s.unacked++
		s.sendQueue <- pkt
	}

	if common.Debug {
		s.log.WithFields(logrus.Fields{
			"num sent": numFrames,
		}).Trace("fillWindow called")
	}
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
	s.frames = append(s.frames, &pkt)
	s.sendQueue <- &pkt
	s.unacked++
	return nil
}
