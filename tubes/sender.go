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

// The largest tube frame data length field.
const maxFrameDataLength uint16 = 2000

// The highest number of frames we will transmit per timeout period,
// even if the window size is large enough.
const maxFragTransPerRTO = 50

type sender struct {
	// The acknowledgement number sent from the other end of the connection.
	// +checklocks:l
	ackNo uint64

	frameNo atomic.Uint32
	// +checklocks:l
	windowSize uint16

	finSent atomic.Bool
	closed  atomic.Bool
	// The buffer of unacknowledged tube frames that will be retransmitted if necessary.
	// +checklocks:l
	frames []*frame

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

	endRetransmit chan struct{}
	retransmitEnded chan struct{}

	windowOpen chan struct{}

	sendQueue chan *frame
}

func (s *sender) unsentFramesRemaining() int {
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
	if s.closed.Load() {
		return 0, io.EOF
	}
	s.buffer = append(s.buffer, b...)

	startFrame := len(s.frames)

	for len(s.buffer) > 0 {
		dataLength := maxFrameDataLength
		if uint16(len(s.buffer)) < dataLength {
			dataLength = uint16(len(s.buffer))
		}
		pkt := frame{
			dataLength: dataLength,
			frameNo:    s.frameNo.Load(),
			data:       s.buffer[:dataLength],
		}

		s.frameDataLengths[pkt.frameNo] = dataLength
		s.frameNo.Add(1)
		s.buffer = s.buffer[dataLength:]
		s.frames = append(s.frames, &pkt)
	}

	for i := startFrame; i < len(s.frames) && i < int(s.windowSize); i++ {
		s.sendQueue <- s.frames[i]
	}
	s.RTOTicker.Reset(s.RTO)
	return len(b), nil
}

func (s *sender) recvAck(ackNo uint32) error {
	s.l.Lock()
	defer s.l.Unlock()
	newAckNo := uint64(ackNo)
	logrus.Tracef("received ack. orig ackno: %d, new ackno: %d", s.ackNo, newAckNo)
	if newAckNo < s.ackNo && (newAckNo+(1<<32)-s.ackNo <= uint64(s.windowSize)) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	for s.ackNo < newAckNo {
		_, ok := s.frameDataLengths[uint32(s.ackNo)]
		if !ok {
			logrus.Debugf("data length missing for frame %d", s.ackNo)
			return errors.New("no data length")
		}
		delete(s.frameDataLengths, uint32(s.ackNo))
		s.ackNo++
		s.frames = s.frames[1:]
	}

	select {
	case s.windowOpen <- struct{}{}:
		break
	default:
		break
	}

	return nil
}

func (s *sender) sendEmptyPacket() *frame {
	pkt := &frame{
		dataLength: 0,
		frameNo: s.frameNo.Load(),
		data: []byte{},
		flags: frameFlags{
			FIN: s.finSent.Load(),
		},
	}
	s.sendQueue <- pkt
	return pkt
}

// rto is true if the window is filled due to a retransmission timeout and false otherwise
// +checklocks:s.l
func (s *sender) fillWindow(rto bool) {
	for i := 0; i < len(s.frames) && i < int(s.windowSize) && (i < maxFragTransPerRTO || !rto); i++ {
		s.sendQueue <- s.frames[i]
		logrus.Tracef("Putting packet on queue. fin? %t", s.frames[i].flags.FIN)
	}
}

func (s *sender) retransmit() {
	stop := false
	for !stop {
		select {
		case <-s.RTOTicker.C:
			s.l.Lock()
			if len(s.frames) == 0 { // Keep Alive messages
				logrus.Tracef("Keep alive sent. frameno: %d", s.frameNo.Load())
				s.sendEmptyPacket()
			} else {
				s.fillWindow(true)
			}
			s.l.Unlock()
		case <-s.windowOpen:
			s.l.Lock()
			s.fillWindow(false)
			s.l.Unlock()
		case <-s.endRetransmit:
			stop = true
		}
	}
	// TODO(hosono) prevent panic by making sure retransmit is only called once
	close(s.retransmitEnded)
}

func (s *sender) stopRetransmit() {
	select {
	case s.endRetransmit <- struct{}{}:
		break
	default:
		break
	}
}

func (s *sender) Start() {
	go s.retransmit()
}

func (s *sender) Reset() {
	s.stopRetransmit()
	<-s.retransmitEnded
}

func (s *sender) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.sendFin()
		return nil
	}
	return io.EOF
}

func (s *sender) sendFin() error {
	s.l.Lock()
	defer s.l.Unlock()
	if s.finSent.Load() {
		return io.EOF
	}
	s.finSent.Store(true)

	pkt := frame{
		dataLength: 0,
		frameNo:    s.frameNo.Load(),
		data:       []byte{},
		flags: frameFlags{
			ACK:  true,
			FIN:  true,
			REQ:  false,
			RESP: false,
		},
	}

	s.frameDataLengths[pkt.frameNo] = 0
	s.frameNo.Add(1)
	s.frames = append(s.frames, &pkt)
	s.sendQueue <- &pkt
	logrus.Debug("sending FIN packet")
	return nil
}
