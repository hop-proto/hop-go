package tubes

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
)

type sender struct {
	// The acknowledgement number sent from the other end of the connection.
	ackNo uint64

	frameNo uint32

	// +checklocks:m
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

	// RTO is the Recovery Time Objective, which aims to be used only on two consecutive packet loss
	RTO time.Duration

	// RTT is the estimate of the round trip time to the remote host
	RTT time.Duration

	// the time after which writes will expire
	deadline time.Time

	// signals that more data be sent
	windowOpen chan struct{}

	sendQueue chan *frame
	probe     probe

	m sync.Mutex

	// logging context
	log *logrus.Entry
}

type probe struct {
	timeLastProbe        time.Time
	rate                 float64
	packetCountLastProbe int
	totalProbeCount      int
	minRTT               time.Duration
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
		RTO:              initialRTT,
		windowSize:       windowSize,
		windowOpen:       make(chan struct{}, 1),
		sendQueue:        make(chan *frame, 1024), // TODO(hosono) make this size 0
		probe: probe{
			timeLastProbe:        time.Now(),
			rate:                 0,
			packetCountLastProbe: 0,
			totalProbeCount:      0,
			minRTT:               time.Second,
		},
		log: log.WithField("sender", ""),
	}
}

func (s *sender) unAckedFramesRemaining() int {
	s.m.Lock()
	defer s.m.Unlock()
	return len(s.frames)
}

// Reset the retransmission timer to 9/8 of the measured RTT
// 9/8 comes from RFC 9002 section 6.1.2
func (s *sender) resetRetransmitTicker() {
	s.RetransmitTicker.Reset((s.RTO / 8) * 9)
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
		s.m.Lock()
		s.frames = append(s.frames, struct {
			*frame
			time.Time
		}{&pkt, time.Time{}})
		s.m.Unlock()
	}

	numFrames := s.framesToSend(false, startFrame)

	if numFrames > 0 && numFrames < int(s.windowSize) {
		select {
		case s.windowOpen <- struct{}{}:
			break
		default:
			break
		}
	}

	return len(b), nil
}

func (s *sender) recvAck(ackNo uint32) error {
	s.m.Lock()
	defer s.m.Unlock()

	// Stop the ticker since we're about to do a new RTT measurement.
	s.RetransmitTicker.Stop()

	oldAckNo := s.ackNo
	newAckNo := uint64(ackNo)
	if newAckNo < s.ackNo && (newAckNo+(1<<32)-s.ackNo <= uint64(s.windowSize)) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	windowOpen := s.ackNo < newAckNo

	for s.ackNo < newAckNo {
		if !s.frames[0].Time.Equal(time.Time{}) && ackNo == s.frames[0].frame.frameNo+1 && !s.frames[0].flags.RTR {
			oldRTT := s.RTT
			measuredRTT := time.Since(s.frames[0].Time)

			// RTT Upper bound
			measuredRTT = min(measuredRTT, s.RTT*2)

			// This formula comes from RFC 9002 section 5.3
			s.RTT = (s.RTT/8)*7 + measuredRTT/8

			if s.RTT < minRTT {
				s.RTT = minRTT
			}

			s.probe.minRTT = min(s.RTT, s.probe.minRTT)

			if common.Debug {
				s.log.WithFields(logrus.Fields{
					"oldRTT":      oldRTT,
					"measuredRTT": measuredRTT,
					"newRTT":      s.RTT,
				}).Trace("updated rtt")
			}
		}
		s.ackNo++
		s.probe.packetCountLastProbe++
		s.frames = s.frames[1:]
		if s.unacked > 0 {
			s.unacked--
		}

		// Adjust the RTO on the RTT when receive an ACK
		s.RTO = (s.RTT / 8) * 9

		// Update window size on the Bandwidth-Delay Product (BDP)
		// Window Size (packets) = Bandwidth (packets/sec) × RTT (sec)
		if (time.Since(s.probe.timeLastProbe) > 2*time.Second ||
			(time.Since(s.probe.timeLastProbe) > 100*time.Millisecond && s.probe.totalProbeCount < 20)) &&
			s.probe.packetCountLastProbe > 0 {

			duration := time.Since(s.probe.timeLastProbe).Seconds()
			rate := float64(s.probe.packetCountLastProbe) / duration // packets/sec

			// initial loop to evaluate the pace
			if s.probe.totalProbeCount == 0 {
				s.probe.rate = rate
				s.probe.totalProbeCount++
			}

			s.probe.totalProbeCount++

			// Makes an average of the measured bandwidth

			alpha := 1.2 // overestimation of the window size

			if rate > s.probe.rate*1.5 || s.probe.totalProbeCount < 20 {
				alpha = 2
			}
			if s.probe.rate > rate*1.5 {
				alpha = 0.8
			}

			rttSeconds := s.probe.minRTT.Seconds()

			s.probe.rate = max(rate, s.probe.rate)

			newWindowSize := uint16(s.probe.rate * rttSeconds * alpha)

			if newWindowSize <= minWindowSize {
				newWindowSize = minWindowSize
			}

			if newWindowSize > maxWindowSize {
				newWindowSize = maxWindowSize
			}

			s.windowSize = newWindowSize

			s.probe.timeLastProbe = time.Now()
			s.probe.packetCountLastProbe = 0
			s.probe.minRTT = time.Second // reset the value for the next probe

			s.log.Debugf("Updated window size to %v", newWindowSize)

		}

		s.log.WithFields(logrus.Fields{
			"ack frame No": newAckNo,
			"unacked":      s.unacked,
			"new ack now":  s.ackNo,
		}).Trace("I am acknowledging")
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
		numFrames = maxFragTransPerRTO
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

// Close stops the sender and causes future writes to return io.EOF
func (s *sender) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		close(s.sendQueue)

		return nil
	}
	return io.EOF
}

func (s *sender) sendFin() error {
	s.m.Lock()
	defer s.m.Unlock()

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

	// To properly close the receiver
	addToSendQueue := false

	if len(s.frames) == 0 {
		pkt.queued = true
		s.unacked++
		addToSendQueue = true
	}

	s.frames = append(s.frames, struct {
		*frame
		time.Time
	}{&pkt, time.Time{}})

	if addToSendQueue {
		s.sendQueue <- &pkt
	}

	return nil
}

func (s *sender) getWindowSize() uint16 {
	s.m.Lock()
	defer s.m.Unlock()
	return s.windowSize
}
