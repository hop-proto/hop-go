package tubes

import (
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
	"hop.computer/hop/congestion"
	"hop.computer/hop/congestion/protocol"
)

// packet stores a sent frame along with the information
// needed to track when it is loss and if it has been acknowledged
type packet struct {
	frame    *frame
	sentTime time.Time
	// frame stores the frameNo truncated to a uint32.
	// This field is the unwrapped frame number
	frameNo int64
}

type sender struct {
	// The acknowledgement number sent from the other end of the connection.
	ackNo uint64

	frameNo    int64
	windowSize uint16

	// The number of packets sent but not acked
	unacked uint16

	finSent    bool
	finFrameNo uint32

	closed atomic.Bool

	// The buffer of unacknowledged tube frames that will be retransmitted if necessary
	// along with the time when they were sent
	packets []packet

	// The algorithm for managing congestion control
	congestion    congestion.SendAlgorithm
	rttStats      *congestion.RTTStats
	bytesInFlight int64
	// The number of times a PTO has been sent without receiving an ack.
	ptoCount int64

	// The time when the last packet was sent.
	lastPktTime time.Time
	lossTime    time.Time

	// The current buffer of unacknowledged bytes from the sender.
	// A byte slice works well here because:
	// 	(1) we need to accommodate resending fragments of potentially varying window sizes
	// 	based on the receiving end, so being able to arbitrarily index from the front is important.
	//	(2) the append() function when write() is called will periodically clean up the unused
	//	memory in the front of the slice by reallocating the buffer array.
	// TODO(hosono) ideally, we would have a maximum buffer size beyond with reads would block
	buffer []byte

	// the time after which writes will expire
	deadline time.Time

	sendQueue chan *frame

	// logging context
	log *logrus.Entry
}

func newSender(log *logrus.Entry) *sender {
	s := &sender{
		ackNo:   1,
		frameNo: 1,
		buffer:  make([]byte, 0),
		// finSent defaults to false
		windowSize:  windowSize,
		sendQueue:   make(chan *frame, 1024), // TODO(hosono) make this size 0
		log:         log.WithField("sender", ""),
		rttStats:    &congestion.RTTStats{},
		lastPktTime: time.Now(),
	}
	s.congestion = congestion.NewCubicSender(congestion.DefaultClock{}, s.rttStats, int64(MaxFrameDataLength), true)
	return s
}

func (s *sender) unAckedFramesRemaining() int {
	return len(s.packets)
}

func (s *sender) queuePacket(pkt packet, now time.Time) {
	s.log.WithField("frameno", pkt.frameNo).Debug("queueing packet")
	s.unacked++
	s.sendQueue <- pkt.frame
	s.setLossDetectionTimer(now)
	s.lastPktTime = now
}

func (s *sender) write(b []byte) (int, error) {
	if !s.deadline.IsZero() && time.Now().After(s.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if s.finSent || s.closed.Load() {
		return 0, io.EOF
	}
	s.buffer = append(s.buffer, b...)

	startFrame := len(s.packets)
	now := time.Now()
	for len(s.buffer) > 0 {
		dataLength := MaxFrameDataLength
		if len(s.buffer) < int(dataLength) {
			dataLength = uint16(len(s.buffer))
		}
		pkt := frame{
			dataLength: dataLength,
			frameNo:    uint32(s.frameNo),
			data:       s.buffer[:dataLength],
		}

		s.buffer = s.buffer[dataLength:]
		s.packets = append(s.packets, packet{
			&pkt,
			now,
			s.frameNo,
		})
		s.frameNo++
	}

	for i := startFrame; i < len(s.packets); i++ {
		pkt := s.packets[i]
		s.queuePacket(pkt, now)
	}

	return len(b), nil
}

func (s *sender) setLossDetectionTimer(now time.Time) {
	if s.lossTime.After(now) {
		if common.Debug {
			s.log.WithField("lossTime", s.lossTime).Debug("not setting loss detection timer")
		}
		return
	}

	ptoTime := s.lastPktTime.Add(s.rttStats.PTO(false) * (1 << s.ptoCount))
	if common.Debug {
		s.log.WithField("ptoTime", ptoTime).WithField("now", now).Trace("setting loss detection timer")
	}
	if ptoTime.After(now) {
		s.lossTime = ptoTime
	}
}

const timeThreshold = 9.0 / 8

func (s *sender) onLossDetectionTimeout() {
	now := time.Now()
	if common.Debug {
		s.log.WithField("lossTime", s.lossTime).WithField("now", now).Trace("firing loss detection timer")
	}
	defer s.setLossDetectionTimer(now)

	maxRTT := float64(max(s.rttStats.LatestRTT(), s.rttStats.SmoothedRTT()))
	lossDelay := time.Duration(timeThreshold * maxRTT)

	// Minimum time of granularity before packets are deemed lost.
	lossDelay = max(lossDelay, protocol.TimerGranularity)

	// Packets sent before this time are deemed lost.
	lostSendTime := now.Add(-lossDelay)

	priorInFlight := s.bytesInFlight

	for _, pkt := range s.packets {
		if pkt.sentTime.Before(lostSendTime) {
			millis := lostSendTime.Sub(pkt.sentTime).Milliseconds()
			s.log.WithFields(logrus.Fields{
				"frameNo":    pkt.frame.frameNo,
				"delay (ms)": millis,
			}).Trace("lost packet")
			// remove lost packet bytes from bytes in flight
			s.bytesInFlight -= int64(pkt.frame.dataLength)
			if s.bytesInFlight < 0 {
				s.bytesInFlight = 0
			}
			s.congestion.OnCongestionEvent(pkt.frameNo, int64(pkt.frame.dataLength), priorInFlight)

			// Queue packet for retransmission
			s.queuePacket(pkt, now)
			s.unacked--

		}
	}
	s.ptoCount++
}

func (s *sender) recvAck(ackNo uint32) error {
	oldAckNo := s.ackNo
	newAckNo := uint64(ackNo)
	if newAckNo < s.ackNo && (newAckNo+(1<<32)-s.ackNo <= uint64(s.windowSize)) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	now := time.Now()
	if s.ackNo < newAckNo {
		s.congestion.MaybeExitSlowStart()
		s.ptoCount = 0

	}

	sentTime := now

	for s.ackNo < newAckNo {
		pkt := s.packets[0]
		if pkt.sentTime.Before(sentTime) {
			sentTime = pkt.sentTime
		}
		// TODO(hosono) unwrap frameno
		s.congestion.OnPacketAcked(pkt.frameNo, int64(pkt.frame.dataLength), s.bytesInFlight, now)
		s.bytesInFlight -= int64(s.packets[0].frame.dataLength)
		s.ackNo++
		s.unacked--
		s.packets = s.packets[1:]
	}

	if sentTime != now {
		s.rttStats.UpdateRTT(now.Sub(sentTime), 0)
	}
	if common.Debug {
		s.log.WithFields(logrus.Fields{
			"old ackNo": oldAckNo,
			"new ackNo": newAckNo,
		}).Trace("updated ackNo")
	}

	return nil
}

func (s *sender) sendEmptyPacket() {
	if s.closed.Load() {
		return
	}
	pkt := &frame{
		dataLength: 0,
		frameNo:    uint32(s.frameNo),
		data:       []byte{},
	}
	s.sendQueue <- pkt
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
		frameNo:    uint32(s.frameNo),
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

	s.packets = append(s.packets, packet{
		frame:    &pkt,
		sentTime: time.Now(),
		frameNo:  s.frameNo,
	})
	s.frameNo++
	s.sendQueue <- &pkt
	s.unacked++
	return nil
}
