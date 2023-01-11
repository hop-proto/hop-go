package tubes

import (
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

type sender struct {
	// The acknowledgement number sent from the other end of the connection.
	// +checklocks:l
	ackNo uint64

	// +checklocks:l
	frameNo uint32
	// +checklocks:l
	windowSize uint16

	// The number of packets sent but not acked
	// +checklocks:l
	unacked uint16

	// +checklocks:l
	finSent bool
	// +checklocks:l
	finFrameNo uint32

	closed atomic.Bool
	// The buffer of unacknowledged tube frames that will be retransmitted if necessary.
	// +checklocks:l
	frames []*dataFrame

	// Different frames can have different data lengths -- we need to know how
	// to update the buffer when frames are acknowledged.
	// +checklocks:l
	frameDataLengths map[uint32]uint16

	// The current buffer of unacknowledged bytes from the sender.
	// A byte slice works well here because:
	// 	(1) we need to accommodate resending fragments of potentially varying window sizes
	// 	based on the receiving end, so being able to arbitrarily index from the front is important.
	//	(2) the append() function when write() is called will periodically clean up the unused
	//	memory in the front of the slice by reallocating the buffer array.
	// TODO(hosono) ideally, we would have a maximum buffer size beyond with reads would block
	// +checklocks:l
	buffer []byte

	// The lock controls all fields of the sender.
	l sync.Mutex

	// Retransmission TimeOut.
	RTOTicker *time.Ticker

	// +checklocks:l
	RTO time.Duration

	// the time after which writes will expire
	// +checklocks:l
	deadline time.Time

	// signals the retransmit goroutine to stop
	endRetransmit chan struct{}

	// indicates that the retransmit goroutine has stopped
	retransmitEnded chan struct{}

	// ensures that stopRetransmit is called only once
	stopRetransmitCalled atomic.Bool

	// signals that more data be sent
	windowOpen chan struct{}

	// +checklocks:l
	sendQueue chan *dataFrame

	// logging context
	log *logrus.Entry
}

func (s *sender) unAckedFramesRemaining() int {
	s.l.Lock()
	defer s.l.Unlock()
	return len(s.frames)
}

func (s *sender) write(b []byte) (int, error) {
	s.l.Lock()
	defer s.l.Unlock()
	if !s.deadline.IsZero() && time.Now().After(s.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if s.finSent || s.closed.Load() {
		return 0, io.EOF
	}
	s.buffer = append(s.buffer, b...)

	startFrame := len(s.frames)

	for len(s.buffer) > 0 {
		dataLength := maxFrameDataLength
		if uint16(len(s.buffer)) < dataLength {
			dataLength = uint16(len(s.buffer))
		}
		pkt := dataFrame{
			dataLength: dataLength,
			frameNo:    s.frameNo,
			data:       s.buffer[:dataLength],
		}

		s.frameDataLengths[pkt.frameNo] = dataLength
		s.frameNo++
		s.buffer = s.buffer[dataLength:]
		s.frames = append(s.frames, &pkt)
	}

	s.fillWindow(false, startFrame)

	s.RTOTicker.Reset(s.RTO)
	return len(b), nil
}

func (s *sender) recvAck(ackNo uint32) error {
	s.l.Lock()
	defer s.l.Unlock()

	oldAckNo := s.ackNo
	newAckNo := uint64(ackNo)
	if newAckNo < s.ackNo && (newAckNo+(1<<32)-s.ackNo <= uint64(s.windowSize)) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	windowOpen := s.ackNo < newAckNo

	for s.ackNo < newAckNo {
		_, ok := s.frameDataLengths[uint32(s.ackNo)]
		if !ok {
			s.log.WithField("ackNo", s.ackNo).Debug("data length missing for frame")
			return errors.New("no data length")
		}
		delete(s.frameDataLengths, uint32(s.ackNo))
		s.ackNo++
		s.unacked--
		s.frames = s.frames[1:]
	}

	s.log.WithFields(logrus.Fields{
		"old ackNo": oldAckNo,
		"new ackNo": newAckNo,
	}).Trace("updated ackNo")

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
	s.l.Lock()
	defer s.l.Unlock()
	s.sendEmptyPacketLocked()
}

// +checklocks:s.l
func (s *sender) sendEmptyPacketLocked() {
	if s.closed.Load() {
		return
	}
	pkt := &dataFrame{
		dataLength: 0,
		frameNo:    s.frameNo,
		data:       []byte{},
	}
	s.sendQueue <- pkt
}

// rto is true if the window is filled due to a retransmission timeout and false otherwise
// +checklocks:s.l
func (s *sender) fillWindow(rto bool, startIndex int) {
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
		// Clamp numFrames to avoid indexing out of bounds
		numFrames = int(s.windowSize - s.unacked)
	}

	// Clamp value to avoid going out of bounds
	if numFrames+startIndex > len(s.frames) {
		numFrames = len(s.frames) - startIndex
	}
	if numFrames < 0 {
		numFrames = 0
	}

	for i := 0; i < numFrames; i++ {
		s.sendQueue <- s.frames[startIndex+i]
		s.unacked++
	}

	s.log.WithFields(logrus.Fields{
		"num sent": numFrames,
	}).Trace("fillWindow called")
}

func (s *sender) retransmit() {
	stop := false
	for !stop {
		select {
		case <-s.RTOTicker.C:
			s.l.Lock()
			if len(s.frames) == 0 { // Keep Alive messages
				s.log.Trace("Keep alive sent")
				s.sendEmptyPacketLocked()
			} else {
				s.log.Trace("retransmitting")
				s.fillWindow(true, 0)
			}
			s.l.Unlock()
		case <-s.windowOpen:
			s.l.Lock()
			s.log.Trace("window open. filling")
			s.fillWindow(false, 0)
			s.l.Unlock()
		case <-s.endRetransmit:
			s.log.Debug("ending retransmit loop")
			stop = true
		}
	}
	close(s.retransmitEnded)
}

// stopRetransmit signals the retransmit goroutine to stop
func (s *sender) stopRetransmit() {
	if !s.stopRetransmitCalled.CompareAndSwap(false, true) {
		return
	}
	close(s.endRetransmit)
	<-s.retransmitEnded
}

// Start begins the retransmit loop
func (s *sender) Start() {
	s.closed.Store(false)
	go s.retransmit()
}

// Close stops the sender and causes future writes to return io.EOF
func (s *sender) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.stopRetransmit()

		s.l.Lock()
		defer s.l.Unlock()
		close(s.sendQueue)

		return nil
	}
	return io.EOF
}

func (s *sender) sendFin() error {
	s.l.Lock()
	defer s.l.Unlock()
	if s.finSent {
		return io.EOF
	}
	s.finSent = true

	pkt := dataFrame{
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

	s.frameDataLengths[pkt.frameNo] = 0
	s.frameNo++
	s.frames = append(s.frames, &pkt)
	s.fillWindow(false, len(s.frames)-1)
	return nil
}
