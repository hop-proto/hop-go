package channels

import (
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type Sender struct {
	// The acknowledgement number sent from the other end of the connection.
	ackNo uint32
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
	// TODO: error handle too long a buffer
	s.l.Lock()
	s.buffer = append(s.buffer, b...)
	logrus.Info("write BUFFER: ", s.buffer, len(s.buffer))
	// we need to unlock here so that send()
	// can claim the buffer lock.
	s.l.Unlock()
	s.send()
	return len(b), nil
}

func (s *Sender) recvAck(ackNo uint32) error {
	s.l.Lock()
	defer s.l.Unlock()
	origAckNo := uint64(s.ackNo)
	newAckNo := uint64(ackNo)
	var numBytesAcked uint64
	if origAckNo < newAckNo {
		numBytesAcked = newAckNo - origAckNo
	} else { // Wraparound.
		numBytesAcked = newAckNo + (1 << 32) - origAckNo
	}

	if numBytesAcked > uint64(len(s.buffer)) {
		return errors.New("acknowledged too many bytes")
	}

	s.buffer = s.buffer[numBytesAcked:]
	s.ackNo = ackNo
	return nil
}

func (s *Sender) retransmit() {
	for {
		timer := time.NewTimer(s.RTO)
		<-timer.C
		s.l.Lock()
		bufferLen := len(s.buffer)
		s.l.Unlock()
		if bufferLen > 0 {
			s.send()
		}
		// logrus.Info("RETRANSIMT buffer len", bufferLen)
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
	dataLength := s.windowSize
	if len(s.buffer) < int(s.windowSize) {
		dataLength = uint16(len(s.buffer))
	}
	pkt := Packet{
		dataLength: dataLength,
		frameNo:    s.ackNo,
		data:       s.buffer[:dataLength],
	}
	s.sendQueue <- &pkt

}
