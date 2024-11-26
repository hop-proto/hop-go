package tubes

import (
	"bytes"
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

	// The sequence number of the first byte in the buffer
	// i.e. the highest unacked sequence number
	bufSeqNo uint64

	// The sequence number of the next byte to send
	// this also equal len of buffer + bufSeqNo
	frameNo uint64

	// The highest sequence number in flight
	inFlightSeqNo uint64

	// The window size of the remote host
	windowSize uint64

	finSent  bool
	finSeqNo uint64

	closed atomic.Bool

	// The current buffer of unacknowledged bytes from the sender.
	// A byte slice works well here because:
	// 	(1) we need to accommodate resending fragments of potentially varying window sizes
	// 	based on the receiving end, so being able to arbitrarily index from the front is important.
	//	(2) the append() function when write() is called will periodically clean up the unused
	//	memory in the front of the slice by reallocating the buffer array.
	// TODO(hosono) ideally, we would have a maximum buffer size beyond with reads would block
	buffer *bytes.Buffer

	// Retransmission TimeOut.
	RTOTicker *time.Ticker

	RTO time.Duration

	// the time after which writes will expire
	deadline time.Time

	// signals that more data be sent
	windowOpen chan struct{}

	// logging context
	log *logrus.Entry
}

func newSender(log *logrus.Entry) *sender {
	return &sender{
		ackNo:         1,
		frameNo:       1,
		bufSeqNo:      1,
		inFlightSeqNo: 1,
		buffer:        &bytes.Buffer{},
		// finSent defaults to false
		RTOTicker:  time.NewTicker(retransmitOffset),
		RTO:        retransmitOffset,
		windowSize: 0,
		windowOpen: make(chan struct{}, 1),
		log:        log.WithField("sender", ""),
	}
}

func (s *sender) checkInvariants() {
	if uint64(s.buffer.Len())+s.bufSeqNo != s.frameNo {
		panic("buffer, frameno, bufseqno")
	}
	if s.inFlightSeqNo > s.frameNo {
		panic("inflight greater than framno")
	}
	if s.finSent {
		if s.frameNo != s.finSeqNo {
			panic("fin send with bad frameNo")
		}
	}
	if s.ackNo > s.frameNo {
		panic("ackno more than frameno")
	}
}

func (s *sender) unackedBytes() uint64 {
	return s.inFlightSeqNo - s.ackNo
}

// write writes data into the internal buffer returning the relevant error
// if something has gone wrong. It does not write data to the network
func (s *sender) write(b []byte) (int, error) {
	s.checkInvariants()
	if !s.deadline.IsZero() && time.Now().After(s.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if s.finSent || s.closed.Load() {
		return 0, io.EOF
	}

	n, _ := s.buffer.Write(b)
	s.frameNo += uint64(n)

	s.RTOTicker.Reset(s.RTO)
	s.checkInvariants()
	return n, nil
}

func (s *sender) recvAck(ackNo uint32) error {
	s.checkInvariants()
	if ackNo > 1<<20+2 {
		panic("recvAck too big")
	}
	oldAckNo := s.ackNo
	newAckNo := uint64(ackNo)
	if newAckNo < s.ackNo && (newAckNo+(1<<32)-s.ackNo <= s.windowSize) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	windowOpen := s.ackNo < newAckNo
	if windowOpen {
		bytesAcked := newAckNo - oldAckNo
		s.ackNo = newAckNo
		s.bufSeqNo += bytesAcked
		s.buffer.Next(int(bytesAcked))

		s.RTOTicker.Reset(s.RTO)
		select {
		case s.windowOpen <- struct{}{}:
			break
		default:
			break
		}
	}

	if common.Debug {
		s.log.WithFields(logrus.Fields{
			"old ackNo": oldAckNo,
			"new ackNo": newAckNo,
		}).Trace("updated ackNo")
	}

	s.checkInvariants()
	return nil
}

// Returns an array of frames to send
// rto is true if this is a retransmission
func (s *sender) pktsToSend(rto bool) []*frame {
	s.checkInvariants()
	data := s.buffer.Bytes()
	dataSeqNo := s.bufSeqNo
	if !rto {
		if s.inFlightSeqNo-s.bufSeqNo < uint64(len(data)) {
			data = data[s.inFlightSeqNo-s.bufSeqNo:]
			dataSeqNo = s.inFlightSeqNo
		} else {
			data = data[0:0]
		}
	}

	var toSend uint64 = windowSize
	if toSend > uint64(len(data)) {
		toSend = uint64(len(data))
	}

	numPkts := toSend / uint64(MaxFrameDataLength)
	if numPkts*uint64(MaxFrameDataLength) != toSend {
		numPkts += 1
	}
	if numPkts == 0 && s.finSent {
		numPkts = 1
	}

	pkts := make([]*frame, numPkts)

	nSent := uint64(0)
	for i := 0; i < len(pkts); i++ {
		dataLength := toSend - nSent
		if dataLength > uint64(MaxFrameDataLength) {
			dataLength = uint64(MaxFrameDataLength)
		}
		pkt := &frame{
			dataLength: uint16(dataLength),
			frameNo:    uint32(dataSeqNo + nSent),
			data:       append([]byte{}, data[:dataLength]...),
		}
		pkt.flags.FIN = s.bufSeqNo+nSent+dataLength == s.finSeqNo
		nSent += dataLength
		toSend -= dataLength
		pkts[i] = pkt
	}

	if common.Debug {
		s.log.WithFields(logrus.Fields{
			"bytes sent": nSent,
			"toSend":     toSend,
		}).Trace("pktsToSend called")
	}

// Close stops the sender and causes future writes to return io.EOF
func (s *sender) Close() error {
	s.checkInvariants()
	if s.closed.CompareAndSwap(false, true) {
		return nil
	}
	return io.EOF
}

func (s *sender) setFin() *frame {
	s.checkInvariants()
	if !s.finSent {
		s.finSeqNo = s.frameNo
	}
	s.finSent = true

	pkt := &frame{
		dataLength: 0,
		frameNo:    uint32(s.finSeqNo),
		data:       []byte{},
		flags: frameFlags{
			ACK:  true,
			FIN:  true,
			REQ:  false,
			RESP: false,
		},
	}
	s.log.WithField("frameNo", pkt.frameNo).Debug("queueing FIN packet")

	s.checkInvariants()
	return pkt
}
