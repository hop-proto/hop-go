package tubes

import (
	"github.com/sirupsen/logrus"
	"hop.computer/hop/common"
	"math"
	"time"
)

type bbrState int

const (
	Startup bbrState = iota
	Drain
	ProbeBW
	ProbeRTT
)

// old value 1.25, 0.75, 1...
var probeBWGainCycle = [...]float64{1.25, 0.75, 1, 1, 1, 1, 1, 1} // 8-phase cycle

type probe struct {
	state          bbrState
	cycleIndex     int
	stateStartTime time.Time
	maxBtlBwFilter float64
	prevBtlBw      float64
	minRTT         time.Duration
	inflightData   int
	// pacingGain controls how fast packets are sent relative to BtlBw
	// A pacingGain > 1 increases inflight and decreases packet inter-arrival time
	// The usage that I want is for the congestion window as we are not implementing any pacing for now
	// However, the number used for the cwnd might be similar to the pacing gain as it acts as a larger
	// in flight data. TBD
	pacingGain    float64
	cwndGain      float64
	avgDataLength uint16
	dataDelivered int
	deliveredTime time.Time
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

			if s.probe.dataDelivered == 0 {
				s.probe.minRTT = measuredRTT
			}

			//s.log.Debugf("abcd RTT %v", measuredRTT)
			s.probe.minRTT = min(s.RTT, s.probe.minRTT)

			if common.Debug {
				s.log.WithFields(logrus.Fields{
					"oldRTT":      oldRTT,
					"measuredRTT": measuredRTT,
					"newRTT":      s.RTT,
				}).Trace("updated rtt")
			}
		}

		if s.frames[0].dataLength > 1000 {

			if s.probe.dataDelivered == 0 {
				s.probe.avgDataLength = s.frames[0].dataLength
				s.probe.stateStartTime = time.Now()
			}

			s.probe.dataDelivered += int(s.frames[0].dataLength)
			s.probe.deliveredTime = time.Now()

			rate := float64(s.probe.dataDelivered-s.frames[0].dataDelivered) / s.probe.deliveredTime.Sub(s.frames[0].deliveredTime).Seconds()

			if rate > s.probe.maxBtlBwFilter && s.probe.dataDelivered > int(s.frames[0].dataLength) {
				s.probe.maxBtlBwFilter = rate
			} else if rate < 0.5*s.probe.maxBtlBwFilter {
				s.probe.maxBtlBwFilter = 0.99 * s.probe.maxBtlBwFilter
			}

			// init

			s.probe.inflightData -= int(s.frames[0].dataLength)

			s.probe.avgDataLength = (s.probe.avgDataLength*7 + s.frames[0].dataLength) / 8

			s.updateBBRState()

			if s.probe.state != Startup {
				s.updateWindowSize(true)
			}
			/*
				s.log.Debugf("abcd windowSize %v", s.windowSize)
				s.log.Debugf("abcd minRTT %v", s.probe.minRTT)
				// and RTT
				s.log.Debugf("abcd dataDelivered %v", s.probe.dataDelivered)
				s.log.Debugf("abcd deliveredTime %v", s.probe.deliveredTime)
				s.log.Debugf("abcd inflightData %v", s.probe.inflightData)
				s.log.Debugf("abcd rate %v", rate)
				s.log.Debugf("abcd cwndGain %v", s.probe.cwndGain)
				s.log.Debugf("abcd pacingGain %v", s.probe.pacingGain)

			*/

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

// RTProp -> (min RTT withing probing window)
// BtlBw -> max DR in bw window

// Update window size on the Bandwidth-Delay Product (BDP)
// Inflight (bytes) = Bandwidth (bytes/sec) × RTT (sec)
func (s *sender) updateBBRState() {
	now := time.Now()

	switch s.probe.state {

	// Startup -> Binary search of the rate space. This finds BtlBw very quickly (log2BDP round trips)
	case Startup:
		if s.probe.maxBtlBwFilter >= s.probe.prevBtlBw*1.25 {
			s.probe.prevBtlBw = s.probe.maxBtlBwFilter
			s.probe.stateStartTime = now
			s.updateWindowSize(false)

			// plateau in BtlBw estimate (3 round-trips where newDr < DR * 1.25) => enter in drain phase
		} else if now.Sub(s.probe.stateStartTime) > 2*s.RTT {
			s.enterDrain()
			s.updateWindowSize(true)
		}

	case Drain:
		// Goal number of packets in flight matches the estimated BDP -> ProbeBW
		if s.probe.inflightData <= int(s.getBDP()) {
			s.log.Debugf("I switch to ProbeBW")
			s.enterProbeBW()
		}

	case ProbeBW:
		// 8 phase cycle pacingGain -> 5/4, 3/4, 1, 1, 1, 1, 1, 1
		if now.Sub(s.probe.stateStartTime) >= s.RTT {
			s.probe.cycleIndex = (s.probe.cycleIndex + 1) % len(probeBWGainCycle)
			s.probe.pacingGain = probeBWGainCycle[s.probe.cycleIndex]
			s.probe.stateStartTime = now
		}

	case ProbeRTT:
		if now.Sub(s.probe.stateStartTime) > 200*time.Millisecond {
			s.log.Debugf("I switch to ProbeBW from RTT")
			s.probe.minRTT = s.RTT
			s.enterProbeBW()
			logrus.Debugf("window %v", s.windowSize)
		}
	}

	// ProbeRTT -> duration > 10 seconds since last  -> cwndGain to 4 packets for at least 200 ms and one round trip
	if now.Sub(s.probe.stateStartTime) > 10*time.Second {
		s.enterProbeRTT()
		logrus.Debugf("window %v", s.windowSize)
	}
}

// Drain pacingGain = 1/pacingGainStartup -> empty the queue
func (s *sender) enterDrain() {
	s.log.Debugf("I switch to Drain")
	s.probe.state = Drain
	s.probe.pacingGain = 1.0 / (2 / math.Ln2)
	// So here in bbr v1 for the drain, they are keeping the same window size but pacing them very slowly
	// How would we do without a pacing for the drain
	s.probe.cwndGain = 2 / math.Ln2 //2 / math.Ln2 // -> lower the pace with a smaller window size?
	s.probe.stateStartTime = time.Now()
}

func (s *sender) enterProbeBW() {
	s.probe.state = ProbeBW
	s.probe.pacingGain = probeBWGainCycle[0] //-> here same, the probBW is not great without pacing
	s.probe.cwndGain = 2.0                   // BBR default for ProbeBW
	s.probe.stateStartTime = time.Now()
	s.probe.cycleIndex = 0
}

func (s *sender) enterProbeRTT() {
	s.probe.state = ProbeRTT
	s.probe.pacingGain = 1.0
	s.probe.cwndGain = 0.75 // -> this is actually shrinking down the window size
	s.probe.stateStartTime = time.Now()
}

func (s *sender) getBDP() float64 {
	return s.probe.maxBtlBwFilter * s.probe.minRTT.Seconds()
}

func (s *sender) getCwnd() float64 {
	return s.probe.cwndGain * s.getBDP()
}

func (s *sender) updateWindowSize(drain bool) {
	if drain && s.probe.inflightData > int(s.windowSize*s.probe.avgDataLength) {
		// Only update the window size if the window is drained
		return
	}

	newWindowSize := uint16(s.getCwnd() / float64(s.probe.avgDataLength))
	if newWindowSize < 10 {
		newWindowSize = 10
	}

	if newWindowSize < s.windowSize {
		// limit the big drop locking the bdp in a low rate
		s.windowSize = (s.windowSize*7 + newWindowSize) / 8
	} else {
		s.windowSize = min(newWindowSize, 1000)
	}
}
