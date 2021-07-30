package channels

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// The largest channel frame data length field.
const MAX_FRAME_DATA_LENGTH = 500

// The highest number of frames we will transmit per timeout period,
// even if the window size is large enough.
const MAX_FRAG_TRANS_PER_RTO = 10

type Sender struct {
	// The acknowledgement number sent from the other end of the connection.
	ackNo   uint64
	finSent bool
	closed  bool
	frameNo uint32
	// The buffer of unacknowledged channel frames that will be retransmitted if necessary.
	frames []*Frame
	// Different frames can have different data lengths -- we need to know how
	// to update the buffer when frames are acknowledged.
	frameDataLengths map[uint32]uint16
	// The current buffer of unacknowledged bytes from the sender.
	// A byte slice works well here because:
	// 	(1) we need to accomodate resending fragments of potentially varying window sizes
	// 	based on the receiving end, so being able to arbitrarily index from the front is important.
	//	(2) the append() function when write() is called will periodically clean up the unused
	//	memory in the front of the slice by reallocating the buffer array.
	buffer []byte
	// The lock controls all fields of the sender.
	l sync.Mutex
	// Retransmission TimeOut.
	RTO        time.Duration
	sendQueue  chan *Frame
	windowSize uint16
}

func (s *Sender) unsentFramesRemaining() bool {
	s.l.Lock()
	defer s.l.Unlock()
	return len(s.frames) > 0
}

func (s *Sender) write(b []byte) (n int, err error) {
	s.l.Lock()
	defer s.l.Unlock()
	if s.closed {
		return 0, errors.New("trying to write to closed channel")
	}
	s.buffer = append(s.buffer, b...)

	for len(s.buffer) > 0 {
		dataLength := uint16(MAX_FRAME_DATA_LENGTH)
		if uint16(len(s.buffer)) < dataLength {
			dataLength = uint16(len(s.buffer))
		}
		pkt := Frame{
			dataLength: dataLength,
			frameNo:    s.frameNo,
			data:       s.buffer[:dataLength],
		}

		s.frameDataLengths[pkt.frameNo] = dataLength
		s.frameNo += 1
		s.buffer = s.buffer[dataLength:]
		s.frames = append(s.frames, &pkt)
	}
	return len(b), nil
}

func (s *Sender) recvAck(ackNo uint32) error {
	logrus.Debug("GRABBING LOCK")
	s.l.Lock()
	defer s.l.Unlock()
	newAckNo := uint64(ackNo)
	logrus.Debug("RECV ACK origAckNo ", s.ackNo, " new ackno ", newAckNo)
	if newAckNo < s.ackNo && (newAckNo+(1<<32)-s.ackNo <= uint64(s.windowSize)) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	for s.ackNo < newAckNo {
		_, ok := s.frameDataLengths[uint32(s.ackNo)]
		if !ok {
			logrus.Debugf("data length missing for frame %d", s.ackNo)
			return fmt.Errorf("data length missing for frame %d", s.ackNo)
		}
		delete(s.frameDataLengths, uint32(s.ackNo))
		s.ackNo += 1
		s.frames = s.frames[1:]
	}

	return nil
}

func (s *Sender) retransmit() {
	for !s.isClosed() { // TODO - decide how to shutdown this endless loop with an enum state
		timer := time.NewTimer(s.RTO) //TODO (baumanl) - add in select statement so doesn't wait on timer when new data available.
		<-timer.C
		s.l.Lock()
		if len(s.frames) == 0 {
			pkt := Frame{
				dataLength: 0,
				frameNo:    s.frameNo,
				data:       []byte{},
			}
			//logrus.Info("SENDING EMPTY PACKET ON SEND QUEUE FOR ACK - FIN? ", pkt.flags.FIN)
			s.sendQueue <- &pkt
		}
		i := 0
		for i < len(s.frames) && i < int(s.windowSize) && i < MAX_FRAG_TRANS_PER_RTO {
			s.sendQueue <- s.frames[i]
			//logrus.Info("PUTTING PKT ON SEND QUEUE - FIN? ", s.frames[i].flags.FIN)
			i += 1
		}
		s.l.Unlock()
	}
}
func (s *Sender) isClosed() bool {
	s.l.Lock()
	defer s.l.Unlock()
	return s.closed
}

func (s *Sender) close() {
	s.l.Lock()
	defer s.l.Unlock()
	s.closed = true
}

/* */
func (s *Sender) sendFin() error {
	s.l.Lock()
	defer s.l.Unlock()
	if s.closed || s.finSent {
		return errors.New("channel is already closed")
	}
	s.finSent = true

	pkt := Frame{
		dataLength: 0,
		frameNo:    s.frameNo,
		data:       []byte{},
		flags: FrameFlags{
			ACK:  true,
			FIN:  true,
			REQ:  false,
			RESP: false,
		},
	}

	s.frameDataLengths[pkt.frameNo] = 0
	s.frameNo += 1
	s.frames = append(s.frames, &pkt)
	//logrus.Info("ADDED FIN PACKET TO SEND QUEUE")
	return nil
}
