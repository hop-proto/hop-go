package tubes

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
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
	probeReno probeReno

	m sync.Mutex

	// logging context
	log *logrus.Entry
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
		// TODO paul, verify this, it looks like it would be a limiting factor
		sendQueue: make(chan *frame, 1024), // TODO(hosono) make this size 0
		probeReno: probeReno{
			state:                SlowStart,
			cwndSize:             1,
			duplicatedAckCounter: 0,
			ssThresh:             1000, // should be infinity
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
			dataDelivered int
			deliveredTime time.Time
			queued        bool
		}{
			frame:         &pkt,
			dataDelivered: s.probe.dataDelivered,
			deliveredTime: s.probe.deliveredTime,
			queued:        false,
		})
		s.m.Unlock()
	}

	numFrames := s.framesToSend(false, startFrame)

	// TODO does not work with the slow start
	if numFrames > 0 && numFrames < int(s.windowSize)+1 {
		select {
		case s.windowOpen <- struct{}{}:
			break
		default:
			break
		}
	}

	return len(b), nil
}

func (s *sender) sendEmptyPacket(rcvAck uint64) {
	// TODO safe convert
	if s.closed.Load() {
		return
	}
	pkt := &frame{
		dataLength: 0,
		frameNo:    s.frameNo,
		data:       []byte{},
		ackNo:      uint32(rcvAck),
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
		dataDelivered int
		deliveredTime time.Time
		queued        bool
	}{
		frame:         &pkt,
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
