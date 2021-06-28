package channels

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// The largest channel frame data length field.
const MAX_FRAME_DATA_LENGTH = 1

type Sender struct {
	// The acknowledgement number sent from the other end of the connection.
	ackNo   uint32
	frameNo uint32
	// The buffer of unacknowledged channel frames that will be retransmitted if necessary.
	frames []*Packet
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
	sendQueue  chan *Packet
	windowSize uint16
}

func (s *Sender) write(b []byte) (n int, err error) {
	s.l.Lock()

	s.buffer = append(s.buffer, b...)
	bufferLen := len(s.buffer)
	s.l.Unlock()
	// we need to unlock here so that send()
	// can claim the buffer lock.

	for bufferLen > 0 {
		s.send()
		s.l.Lock()
		bufferLen = len(s.buffer)
		s.l.Unlock()
	}
	return len(b), nil
}

func (s *Sender) recvAck(ackNo uint32) error {
	s.l.Lock()
	defer s.l.Unlock()
	origAckNo := uint64(s.ackNo)
	newAckNo := uint64(ackNo)

	if newAckNo < origAckNo && (newAckNo+(1<<32)-origAckNo <= uint64(s.windowSize)) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	bytesAcked := uint64(0)
	frame := origAckNo
	// logrus.Info("recvAck ", origAckNo, newAckNo, bytesAcked, frame)
	for frame < newAckNo {
		bytesForFrame, ok := s.frameDataLengths[uint32(frame)]
		if !ok {
			return fmt.Errorf("data length missing for frame %d", frame)
		}
		bytesAcked += uint64(bytesForFrame)
		delete(s.frameDataLengths, uint32(frame))
		frame += 1
		s.frames = s.frames[1:]
	}

	s.ackNo = uint32(newAckNo)

	if bytesAcked > uint64(len(s.buffer)) {
		return errors.New("acknowledged too many bytes")
	}

	s.buffer = s.buffer[bytesAcked:]
	return nil
}

func (s *Sender) retransmit() {
	s.l.Lock()
	numFrames := len(s.frames)
	s.l.Unlock()
	for true || numFrames > 0 {
		timer := time.NewTimer(s.RTO)
		<-timer.C
		s.l.Lock()
		if len(s.frames) > 0 {
			s.sendQueue <- s.frames[0]
		}

		numFrames = len(s.frames)
		s.l.Unlock()
	}
}

/*
	send() is internally called by:
	1) a write() call.
	2) The sender timeout thread.
	It sends the earliest unacknowledged segment.
*/
func (s *Sender) send() {
	s.l.Lock()
	defer s.l.Unlock()
	dataLength := uint16(MAX_FRAME_DATA_LENGTH)
	if uint16(len(s.buffer)) < dataLength {
		dataLength = uint16(len(s.buffer))
	}
	pkt := Packet{
		dataLength: dataLength,
		frameNo:    s.frameNo,
		data:       s.buffer[:dataLength],
	}
	s.frameDataLengths[pkt.frameNo] = dataLength
	s.frameNo += 1
	s.buffer = s.buffer[dataLength:]
	s.frames = append(s.frames, &pkt)

}
