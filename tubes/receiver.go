package tubes

import (
	"bytes"
	"container/heap"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
)

type receiver struct {
	/*
		We treat the sequence numbers as uint64 so we can avoid wraparounds
		and not have to update our priority queue orderings in the case of a
		wraparound.
	*/
	ackNo       uint64
	windowStart uint64
	windowSize  uint16
	closed      atomic.Bool
	m           sync.Mutex
	fragments   PriorityQueue

	dataReady *common.DeadlineChan[struct{}]
	buffer    *bytes.Buffer

	log *logrus.Entry
}

func (r *receiver) init() {
	heap.Init(&r.fragments)
}

func (r *receiver) getAck() uint32 {
	r.m.Lock()
	defer r.m.Unlock()
	return uint32(r.ackNo)
}

/*
Processes window into buffer stream if the ordered fragments are ready (in order).
Precondition: r.m mutex is held.
*/
func (r *receiver) processIntoBuffer() {
	for r.fragments.Len() > 0 {
		frag := heap.Pop(&(r.fragments)).(*pqItem)

		if r.windowStart != frag.priority {
			// This packet cannot be added to the buffer yet.
			r.log.WithFields(logrus.Fields{
				"window start":  r.windowStart,
				"frag priority": frag.priority,
			}).Trace()
			if frag.priority > r.windowStart {
				heap.Push(&r.fragments, frag)
				break
			}
		} else if frag.FIN {
			r.windowStart++
			r.ackNo++
			r.closed.Store(true)
		} else {
			r.buffer.Write(frag.value)
			r.windowStart++
			r.ackNo++
		}
	}
	select {
	case r.dataReady.C <- struct{}{}:
		break
	default:
		break
	}
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
	if r.closed.Load() {
		return nbytes, io.EOF
	}
	return nbytes, nil
}

/* Checks if frame is in bounds of receive window. */
func frameInBounds(wS uint64, wE uint64, f uint64) bool {
	if wS < wE { // contiguous:  ------WS+++++++WE------
		if f > wE || f < wS {
			return false
		}
	} else { // wraparound: ++++WE------WS++++
		if f > wE && f < wS {
			return false
		}
	}
	return true
}

/*
Utility function to add offsets so that we eliminate wraparounds.
Precondition: must be holding frame number
*/
func (r *receiver) unwrapFrameNo(frameNo uint32) uint64 {
	// TODO(hosono) there's a bug in the implementation below. For now, don't unwrap
	return uint64(frameNo)
	/*
	 *    // The previous, offsets are represented by the 32 least significant bytes of the window start.
	 *    windowStart := r.windowStart
	 *    newNo := uint64(frameNo) + windowStart - uint64(uint32(windowStart))
	 *
	 *    // Add an additional offset for the case in which seqNo has wrapped around again.
	 *    if frameNo < uint32(windowStart) {
	 *        newNo += 1 << 32
	 *    }
	 *    return newNo
	 */
}

/* Precondition: receive window lock is held. */
func (r *receiver) receive(p *frame) error {
	r.m.Lock()
	defer r.m.Unlock()
	windowStart := r.windowStart
	windowEnd := r.windowStart + uint64(uint32(r.windowSize))

	frameNo := r.unwrapFrameNo(p.frameNo)
	//r.log.Debugf("receive frame frameNo: %d, ackNo: %d, fin: %t, recv ack no: %d, data: %x", frameNo, p.ackNo, p.flags.FIN, r.ackNo, p.data)
	if !frameInBounds(windowStart, windowEnd, frameNo) {
		r.log.WithFields(logrus.Fields{
			"frameNo":     frameNo,
			"windowStart": windowStart,
			"windowEnd":   windowEnd,
		}).Debugf("out of bounds frame")
		return errors.New("received dataframe out of receive window bounds")
	} else {
		r.log.WithFields(logrus.Fields{
			"frameNo":     frameNo,
			"windowStart": windowStart,
			"windowEnd":   windowEnd,
		}).Tracef("got in bounds frame.")
	}

	if (p.dataLength > 0 || p.flags.FIN) && (frameNo >= r.windowStart) {
		heap.Push(&r.fragments, &pqItem{
			value:    p.data,
			priority: frameNo,
			FIN:      p.flags.FIN,
		})
	}

	r.processIntoBuffer()

	return nil
}

func (r *receiver) Close() {
	r.closed.Store(true)
	r.dataReady.Cancel(io.EOF)
}
