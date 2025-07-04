package tubes

import (
	"bytes"
	"container/heap"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
)

type receiver struct {
	/*
		We treat the sequence numbers as uint64 so we can avoid wraparounds
		and not have to update our priority queue orderings in the case of a
		wraparound.
	*/
	// +checklocks:m
	ackNo uint64
	// +checklocks:m
	windowStart uint64

	rwnd uint64 //RWND is used for flow control (don’t overwhelm recipient buffer). // TODO

	closed atomic.Bool
	m      sync.Mutex
	// +checklocks:m
	fragments PriorityQueue

	dataReady *common.DeadlineChan[struct{}]
	// +checklocks:m
	buffer             *bytes.Buffer
	missingFrame       atomic.Bool
	frameToSendCounter uint16

	log *logrus.Entry
}

func newReceiver(log *logrus.Entry) *receiver {
	r := &receiver{
		dataReady:   common.NewDeadlineChan[struct{}](1),
		buffer:      new(bytes.Buffer),
		fragments:   make(PriorityQueue, 0),
		windowStart: 1,
		log:         log.WithField("receiver", ""),
	}

	r.m.Lock()
	defer r.m.Unlock()
	heap.Init(&r.fragments)

	return r
}

func (r *receiver) getAck() uint32 {
	r.m.Lock()
	defer r.m.Unlock()
	return uint32(r.ackNo)
}

func (r *receiver) getFrameToSendCounter() uint16 {
	r.m.Lock()
	defer r.m.Unlock()
	return r.frameToSendCounter
}

/*
Processes window into buffer stream if the ordered fragments are ready (in order).
Precondition: r.m mutex is held.
Returns true if it processed a FIN packet
*/
// +checklocks:r.m
func (r *receiver) processIntoBuffer() bool {
	fin := false
	waiting := false
	oldLen := r.fragments.Len()
	for r.fragments.Len() > 0 {
		frag := heap.Pop(&(r.fragments)).(*pqItem)

		var log *logrus.Entry
		if common.Debug {
			log = r.log.WithFields(logrus.Fields{
				"window start": r.windowStart,
				"frameNo":      frag.priority,
				"fin":          frag.FIN,
			})
		}

		if r.windowStart != frag.priority {
			// This packet cannot be added to the buffer yet.
			if common.Debug {
				log.Trace("cannot process packet into buffer yet")
			}
			if frag.priority > r.windowStart {
				heap.Push(&r.fragments, frag)
				waiting = true

				// todo review the retransmission process

				/*
					r.missingFrame.Store(true)
					// Add to RTR frame.datalength the cumulative missing frames
					frameToSend := uint16(frag.priority - r.windowStart)
					if frameToSend <= windowSize {
						r.frameToSendCounter = frameToSend
					}

				*/
				if common.Debug {
					log.WithFields(logrus.Fields{
						"frag.priority": frag.priority,
						"r.windowStart": r.windowStart,
					}).Trace("cannot process packet")
				}

				break
			}
		} else {
			if frag.FIN {
				r.closed.Store(true)
				fin = true
			}
			r.buffer.Write(frag.value)
			r.windowStart++
			r.ackNo++
			r.frameToSendCounter = 0
			if common.Debug {
				log.Trace("processing packet")
			}
		}
	}
	if oldLen > r.fragments.Len() || waiting {
		select {
		case r.dataReady.C <- struct{}{}:
			break
		default:
			break
		}
	}
	return fin
}

func (r *receiver) read(buf []byte) (int, error) {
	r.m.Lock()
	if r.buffer.Len() == 0 && !r.closed.Load() {
		r.m.Unlock()
		_, err := r.dataReady.Recv()
		if err != nil {
			return 0, err
		}
		r.m.Lock()
	}
	defer r.m.Unlock()

	nbytes, _ := r.buffer.Read(buf)
	if r.closed.Load() && r.buffer.Len() == 0 {
		return nbytes, io.EOF
	}
	return nbytes, nil
}

// unwrapFrameNo converts 32 bit frame numbers into 64 bit frame numbers.
// It selects the frame number closest to the current ackNo.
// +checklocks:r.m
func (r *receiver) unwrapFrameNo(frameNo uint32) uint64 {
	// TODO(hosono) there's probably a much simpler way to do this, but this works
	var mult uint64 = 1 << 32 // 2 ^ 32
	var lower uint64
	var upper uint64

	if r.ackNo == 0 {
		lower = uint64(frameNo)
		upper = mult + uint64(frameNo)
	} else if r.ackNo%mult < 1<<31 {
		lower = (r.ackNo/mult-1)*mult + uint64(frameNo)
		upper = (r.ackNo/mult)*mult + uint64(frameNo)
	} else {
		lower = (r.ackNo/mult)*mult + uint64(frameNo)
		upper = (r.ackNo/mult+1)*mult + uint64(frameNo)
	}

	var lowerDiff uint64
	var upperDiff uint64

	if lower < r.ackNo {
		lowerDiff = r.ackNo - lower
	} else {
		lowerDiff = lower - r.ackNo
	}

	if upper < r.ackNo {
		upperDiff = r.ackNo - upper
	} else {
		upperDiff = upper - r.ackNo
	}

	if upperDiff < lowerDiff {
		return upper
	}
	return lower
}

// receive processes a single incoming packet
func (r *receiver) receive(p *frame) (bool, uint64, error) {
	r.m.Lock()
	defer r.m.Unlock()

	if r.closed.Load() {
		r.log.Trace("receiver closed. not processing packet into buffer")
		return false, r.ackNo, io.EOF
	}

	windowStart := r.windowStart
	frameNo := r.unwrapFrameNo(p.frameNo)

	var log *logrus.Entry
	if common.Debug {
		log = r.log.WithFields(logrus.Fields{
			"frameNo":     frameNo,
			"windowStart": windowStart,
		})
	}

	// The flag ACK must be false to be processed in the heap memory.
	// Prevent processing of RTR ACK with dataLength > 0
	if ((p.dataLength > 0 && !p.flags.ACK) || p.flags.FIN) && windowStart <= frameNo {
		if p.flags.RTR {
			r.log.Debugf("I received a rtr %v, window %v, time %v", p.frameNo, r.windowStart, time.Now())
		}
		r.log.Debugf("I received %v, window %v time %v", p.frameNo, r.windowStart, time.Now())

		// maybe prio here?
		heap.Push(&r.fragments, &pqItem{
			value:    p.data,
			priority: frameNo,
			FIN:      p.flags.FIN,
		})

		if common.Debug {
			log.Trace("in bounds frame")
		}
	} else {
		if p.dataLength > 0 && !p.flags.ACK {
			if common.Debug {
				log.Debug("out of bounds frame")
			}
			return false, r.ackNo, errFrameOutOfBounds
		}

		if common.Debug {
			log.Trace("keep alive frame")
		}
	}

	fin := r.processIntoBuffer()
	return fin, r.ackNo, nil
}

// Close causes future reads to return io.EOF
func (r *receiver) Close() {
	r.closed.Store(true)
	r.dataReady.Close()
}
