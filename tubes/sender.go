package tubes

import (
	"fmt"
	"io"
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
	// +checklocks:l
	frameNo uint32
	// +checklocks:l
	windowSize uint16

	// +checklocks:l
	finSent bool
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
	RTO       time.Duration

	// the tube that owns this sender
	tube 	*Reliable
}

func (s *sender) unsentFramesRemaining() bool {
	s.l.Lock()
	defer s.l.Unlock()
	return len(s.frames) > 0
}

func (s *sender) sendFrame(pkt *frame) {
	pkt.tubeID = s.tube.id
	pkt.ackNo = s.tube.recvWindow.getAck()
	pkt.flags.ACK = true
	pkt.flags.REL = true
	s.tube.sendQueue <- pkt.toBytes()
}

func (s *sender) write(b []byte) (int, error) {
	s.l.Lock()
	defer s.l.Unlock()
	if s.closed.Load() {
		return 0, errClosedWrite
	}
	s.buffer = append(s.buffer, b...)

	for len(s.buffer) > 0 {
		dataLength := maxFrameDataLength
		if uint16(len(s.buffer)) < dataLength {
			dataLength = uint16(len(s.buffer))
		}
		pkt := frame{
			dataLength: dataLength,
			frameNo:    s.frameNo,
			data:       s.buffer[:dataLength],
		}

		s.frameDataLengths[pkt.frameNo] = dataLength
		s.frameNo++
		s.buffer = s.buffer[dataLength:]
		s.frames = append(s.frames, &pkt)
	}

	for i := 0; i < len(s.frames) && i < int(s.windowSize); i++ {
		s.sendFrame(s.frames[i])
	}
	s.RTOTicker.Reset(s.RTO)
	return len(b), nil
}

func (s *sender) recvAck(ackNo uint32) error {
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
			return errNoDataLength
		}
		delete(s.frameDataLengths, uint32(s.ackNo))
		s.ackNo++
		s.frames = s.frames[1:]
	}

	return nil
}

func (s *sender) retransmit() {
	for !s.closed.Load() { // TODO - decide how to shutdown this endless loop with an enum state
		<-s.RTOTicker.C
		s.l.Lock()
		if len(s.frames) == 0 { // Keep Alive messages
			pkt := frame{
				dataLength: 0,
				frameNo:    s.frameNo,
				data:       []byte{},
			}
			// logrus.Info("SENDING EMPTY PACKET ON SEND QUEUE FOR ACK - FIN? ", pkt.flags.FIN)
			s.sendFrame(&pkt)
		}
		for i := 0; i < len(s.frames) && i < int(s.windowSize) && i < maxFragTransPerRTO; i++ {
			s.sendFrame(s.frames[i])
			//logrus.Info("PUTTING PKT ON SEND QUEUE - FIN? ", s.frames[i].flags.FIN)
		}
		s.l.Unlock()
	}
}

func (s *sender) Close() {
	s.closed.Store(true)
}

func (s *sender) sendFin() error {
	s.l.Lock()
	defer s.l.Unlock()
	if s.closed.Load() || s.finSent {
		return errClosedWrite
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

	s.frameDataLengths[pkt.frameNo] = 0
	s.frameNo++
	s.frames = append(s.frames, &pkt)
	s.sendFrame(&pkt)
	//logrus.Info("ADDED FIN PACKET TO SEND QUEUE")
	return nil
}
