package tubes

import (
	"io"
	"math"
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
		dataDelivered int
		deliveredTime time.Time
		queued        bool
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

type bbrState int

const (
	Startup bbrState = iota
	Drain
	ProbeBW
	ProbeRTT
)

// old value 1.25, 0.75, 1...
var probeBWGainCycle = [...]float64{1.75, 0.75, 1, 1, 1, 1, 1, 1} // 8-phase cycle

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
	//pacingGain float64
	cwndGain      float64
	avgDataLength uint16
	dataDelivered int
	deliveredTime time.Time
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
			state:      Startup,
			cycleIndex: 0,
			//pacingGain: 2 / math.Ln2, //  2 / math.Ln2,
			cwndGain:       2 / math.Ln2,
			maxBtlBwFilter: 10000, // default 10kB/s
			minRTT:         maxRTO,
			inflightData:   0,
			avgDataLength:  0,
			prevBtlBw:      0,
			dataDelivered:  0,
			deliveredTime:  time.Now(),
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
		}

		s.frameNo++
		s.buffer = s.buffer[dataLength:]
		s.m.Lock()
		s.frames = append(s.frames, struct {
			*frame
			time.Time
			dataDelivered int
			deliveredTime time.Time
			queued        bool
		}{
			frame:         &pkt,
			Time:          time.Time{},
			dataDelivered: s.probe.dataDelivered,
			deliveredTime: s.probe.deliveredTime,
			queued:        false,
		})
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

		if s.frames[0].dataLength > 1000 {

			s.probe.dataDelivered += int(s.frames[0].dataLength)
			s.probe.deliveredTime = time.Now()

			rate := float64(s.probe.dataDelivered-s.frames[0].dataDelivered) / s.probe.deliveredTime.Sub(s.frames[0].deliveredTime).Seconds()

			//s.log.Debugf("abcd rate %v", rate)

			if rate > s.probe.maxBtlBwFilter {
				s.probe.maxBtlBwFilter = rate
			} else if rate < 0.5*s.probe.maxBtlBwFilter {
				s.probe.maxBtlBwFilter = 0.99 * s.probe.maxBtlBwFilter
			}

			// init

			s.probe.inflightData -= int(s.frames[0].dataLength)

			s.probe.avgDataLength = (s.probe.avgDataLength*7 + s.frames[0].dataLength) / 8

			s.updateBBRState()

			s.updateWindowSize(true)

			/*
				s.log.Debugf("abcd windowSize %v", s.windowSize)
				s.log.Debugf("abcd minRTT %v", s.probe.minRTT)
				s.log.Debugf("abcd dataDelivered %v", s.probe.dataDelivered)
				s.log.Debugf("abcd deliveredTime %v", s.probe.deliveredTime)
				s.log.Debugf("abcd inflightData %v", s.probe.inflightData)

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
	queued := false

	if len(s.frames) == 0 {
		queued = true
		s.unacked++
		addToSendQueue = true
	}

	s.frames = append(s.frames, struct {
		*frame
		time.Time
		dataDelivered int
		deliveredTime time.Time
		queued        bool
	}{
		frame:         &pkt,
		Time:          time.Time{},
		dataDelivered: s.probe.dataDelivered,
		deliveredTime: s.probe.deliveredTime,
		queued:        queued,
	})

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
		} else if now.Sub(s.probe.stateStartTime) > 5*s.RTT {
			s.enterDrain()
			logrus.Debugf("window %v", s.windowSize)
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
			//s.probe.pacingGain = probeBWGainCycle[s.probe.cycleIndex]
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
	//s.probe.pacingGain = 1.0 / (2 / math.Ln2)
	// So here in bbr v1 for the drain, they are keeping the same window size but pacing them very slowly
	// How would we do without a pacing for the drain
	s.probe.cwndGain = 2 / math.Ln2 // -> lower the pace with a smaller window size?
	s.probe.stateStartTime = time.Now()
}

func (s *sender) enterProbeBW() {
	s.probe.state = ProbeBW
	//s.probe.pacingGain = probeBWGainCycle[0] -> here same, the probBW is not great without pacing
	s.probe.cwndGain = 2.0 // BBR default for ProbeBW
	s.probe.stateStartTime = time.Now()
	s.probe.cycleIndex = 0
}

func (s *sender) enterProbeRTT() {
	s.probe.state = ProbeRTT
	//s.probe.pacingGain = 1.0
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
	s.windowSize = min(newWindowSize, 1000)
}
