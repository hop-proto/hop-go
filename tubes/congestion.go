package tubes

import (
	"github.com/sirupsen/logrus"
	"hop.computer/hop/common"
	"time"
)

type controlState int

const (
	SlowStart controlState = iota
	AIMD
)

type probe struct {
	state                controlState
	cwndSize             float64 // todo init to 1
	duplicatedAckCounter int     // todo init to 0
	ssThresh             uint16  // todo SSTHRESH helps the congestion control algorithm remember the latest safe rate. It’s initialized to infinity.
}

func (s *sender) recvAck(ackNo uint32) (uint32, error) {
	s.m.Lock()
	defer s.m.Unlock()

	// Stop the ticker since we're about to do a new RTT measurement.
	s.RetransmitTicker.Stop()

	missingFrameNo := uint32(0)
	oldAckNo := s.ackNo
	newAckNo := uint64(ackNo)
	if newAckNo < s.ackNo && (newAckNo+(1<<32)-s.ackNo <= uint64(s.windowSize)) { // wrap around
		newAckNo = newAckNo + (1 << 32)
	}

	// congestion event counter for 3 duplicated ack
	// to not apply on the first 20 acks

	if oldAckNo == newAckNo && ackNo > 20 {
		s.probe.duplicatedAckCounter++
		logrus.Debugf("I received the ack %v, n %v times", newAckNo, s.probe.duplicatedAckCounter)
		if s.probe.duplicatedAckCounter == 2 && s.probe.state == AIMD {
			newcwndSize := (3 * s.probe.cwndSize) / 4 // the usual 1/2 of the cwndsize is too agressive considering the deadlocks
			s.probe.cwndSize = newcwndSize
			s.probe.ssThresh = uint16(newcwndSize)

			if s.probe.cwndSize < 10 {
				s.probe.cwndSize = 10
			}

		}
		if s.probe.state == SlowStart && s.probe.duplicatedAckCounter == 2 {
			// increasing the rate exponentially (e.g. doubling on each iteration) until we encounter the first loss
			newcwndSize := s.probe.cwndSize / 2
			s.probe.cwndSize = newcwndSize
			s.probe.ssThresh = uint16(newcwndSize)
		}
		if s.probe.duplicatedAckCounter > 2 { // sign of large congestion on the path
			missingFrameNo = ackNo
		}
	}

	windowOpen := s.ackNo < newAckNo

	for s.ackNo < newAckNo {

		if ((s.probe.duplicatedAckCounter > 1 && ackNo > 20) || s.probe.cwndSize > float64(s.probe.ssThresh)) && s.probe.state == SlowStart {
			s.probe.state = AIMD
		}

		s.probe.duplicatedAckCounter = 0

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

			if common.Debug {
				s.log.WithFields(logrus.Fields{
					"oldRTT":      oldRTT,
					"measuredRTT": measuredRTT,
					"newRTT":      s.RTT,
				}).Trace("updated rtt")
			}
		}

		if s.frames[0].dataLength > 1000 {

			// Each time we receive an acknowledgement, we will take the current window size CWND and reassign it to CWND + (1/CWND)
			if s.probe.state == AIMD {
				s.probe.cwndSize = s.probe.cwndSize + (1 / s.probe.cwndSize) // +=CWND + (1/CWND)
			} else {
				s.probe.cwndSize++

				// Slow start is used when congestion window is no greater than the slow start
				// threshold
				if uint16(s.probe.cwndSize) > s.probe.ssThresh && s.probe.ssThresh > 0 {
					s.probe.state = AIMD
				}
			}

		}

		s.ackNo++
		s.frames = s.frames[1:]

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
	// TODO (Paul) I got the case where windowsize went down to 0
	if s.probe.cwndSize < 10 {
		s.probe.cwndSize = 10
	}

	if s.probe.state == SlowStart {
		s.windowSize = uint16(s.probe.cwndSize)
	} else {
		s.windowSize = (s.windowSize*3 + uint16(s.probe.cwndSize)) / 4
	}

	logrus.Debugf("windowsSize %v", s.windowSize)

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

	return missingFrameNo, nil
}
