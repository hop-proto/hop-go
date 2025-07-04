package tubes

import (
	"github.com/sirupsen/logrus"
	"hop.computer/hop/common"
	"time"
)

type renoState int

const (
	SlowStart renoState = iota
	AIMD
	FastRecovery
)

// website where i followed the implementation from https://textbook.cs168.io/transport/cc-implementation.html

//The window size and the rate of sending data are correlated by the following equation: rate times RTT = window size.
// rate of window size / RTT.
// Maximum Segment Size (MSS) )> mms times number of packets = number of bytes

//event-driven updates

//The three TCP events where we need to update the window size are: new ack, 3 duplicate acks, and timeout.

// TODO RWND is used for flow control (don’t overwhelm recipient buffer).
// The recipient maintains a buffer of out-of-order packets.
// The recipient responds to receiving a packet, by replying with an ack and a RWND value.

///The sender responds to 3 events: Ack for new data (not previously acked), duplicate ack, and timeout.

type probeReno struct {
	state                renoState
	cwndSize             float64 // todo init to 1
	duplicatedAckCounter int     // todo init to 0
	ssThresh             uint16  // todo SSTHRESH helps the congestion control algorithm remember the latest safe rate. It’s initialized to infinity.
	retransmit           bool
	counter              int
	inflightPackets      int
}

func (s *sender) recvAckReno(ackNo uint32) error {
	s.m.Lock()
	defer s.m.Unlock()

	// Stop the ticker since we're about to do a new RTT measurement.
	s.RetransmitTicker.Stop()

	oldAckNo := s.ackNo
	newAckNo := uint64(ackNo)
	if newAckNo < s.ackNo && (newAckNo+(1<<32)-s.ackNo <= uint64(s.windowSize)) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	// congestion event counter for 3 duplicated ack
	// to not apply on the first 10 acks

	if oldAckNo == newAckNo && ackNo > 20 {
		//logrus.Debugf("received dup ack %v", newAckNo)
		s.probeReno.duplicatedAckCounter++
		if s.probeReno.duplicatedAckCounter == 3 && s.probeReno.state == AIMD {
			// todo fallback on the window size
			s.probeReno.ssThresh = uint16(s.probeReno.cwndSize / 2)
			// Fast recovery mode -> new Reno
			//s.probeReno.cwndSize = (s.probeReno.cwndSize / 2) + 3
			//s.probeReno.state = FastRecovery

			// Reno
			s.probeReno.cwndSize = s.probeReno.cwndSize / 2

			if s.probeReno.cwndSize < 1 {
				s.probeReno.cwndSize = 1
			}

			s.probeReno.retransmit = true

		}
		if s.probeReno.state == SlowStart && s.probeReno.duplicatedAckCounter == 1 {
			// increasing the rate exponentially (e.g. doubling on each iteration) until we encounter the first loss
			newcwndSize := s.probeReno.cwndSize / 2
			s.probeReno.cwndSize = newcwndSize
			s.probeReno.ssThresh = uint16(newcwndSize)
			s.probeReno.retransmit = true
		}

		// TODO protect this one of the deadlock?

		/* new reno
		else if s.probeReno.state == FastRecovery {
			// artificial extend
			s.probeReno.cwndSize++
		}

		*/

	}

	for s.ackNo < newAckNo {

		if (s.probeReno.duplicatedAckCounter > 0 || s.probeReno.cwndSize > float64(s.probeReno.ssThresh)) && s.probeReno.state == SlowStart {
			s.probeReno.state = AIMD
		}

		s.probeReno.duplicatedAckCounter = 0

		if !s.frames[0].frame.time.Equal(time.Time{}) && ackNo == s.frames[0].frame.frameNo+1 && !s.frames[0].flags.RTR {
			oldRTT := s.RTT
			measuredRTT := time.Since(s.frames[0].frame.time)

			// RTT Upper bound
			measuredRTT = min(measuredRTT, s.RTT*2)

			// This formula comes from RFC 9002 section 5.3
			s.RTT = (s.RTT/8)*7 + measuredRTT/8

			if s.RTT < minRTT {
				s.RTT = minRTT
			}

			if common.Debug {
				s.log.WithFields(logrus.Fields{
					"oldRTT":      oldRTT,
					"measuredRTT": measuredRTT,
					"newRTT":      s.RTT,
				}).Trace("updated rtt")
			}
		}

		if s.frames[0].dataLength > 1000 {

			s.probeReno.inflightPackets--

			// Each time we receive an acknowledgement, we will take the current window size CWND and reassign it to CWND + (1/CWND)
			if s.probeReno.state == AIMD {
				s.probeReno.cwndSize = s.probeReno.cwndSize + (1 / s.probeReno.cwndSize) // +=CWND + (1/CWND)
			} else if s.probeReno.state == FastRecovery {
				s.probeReno.state = AIMD
				s.probeReno.cwndSize = float64(s.probeReno.ssThresh)
			} else {
				s.probeReno.cwndSize++

				// Slow start is used when congestion window is no greater than the slow start
				// threshold
				if uint16(s.probeReno.cwndSize) > s.probeReno.ssThresh && s.probeReno.ssThresh > 0 {
					s.probeReno.state = AIMD
				}
			}
			s.log.Debugf("abcd index %v", s.probeReno.counter)
			s.log.Debugf("abcd cwndSize %v", s.probeReno.cwndSize)
			s.log.Debugf("abcd ack %v", s.ackNo)
			// and RTT
			s.log.Debugf("abcd state %v", s.probeReno.state)
			s.log.Debugf("abcd ssThresh %v", s.probeReno.ssThresh)
			s.log.Debugf("abcd duplicatedAckCounter %v", s.probeReno.duplicatedAckCounter)
			s.log.Debugf("abcd time %v", time.Now())
			s.log.Debugf("abcd windowSize %v", s.windowSize)
			s.log.Debugf("abcd inflight %v", s.probeReno.inflightPackets)

			s.probeReno.counter++

		}

		s.ackNo++
		s.frames = s.frames[1:]

		//s.windowSize = uint16(s.getCwnd() / float64(s.probe.maxDataLength)) // convert bytes to packets

		if s.unacked > 0 {
			s.unacked--
		}

		// Adjust the RTO on the RTT when receive an ACK
		s.RTO = (s.RTT / 8) * 9

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

	// keep updating the window size on receive
	// TODO verify this, but it helps for the start

	if s.probeReno.cwndSize > 10 {
		s.windowSize = uint16(s.probeReno.cwndSize)
	}

	s.resetRetransmitTicker()

	return nil
}
