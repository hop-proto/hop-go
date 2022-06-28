package tubes

import (
	"bytes"
	"container/heap"
	"errors"
	"io"
	"sync"

	"github.com/sirupsen/logrus"
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
	closed      bool
	closedCond  *sync.Cond
	bufferCond  sync.Cond
	m           sync.Mutex
	fragments   PriorityQueue

	buffer *bytes.Buffer
}

func (r *receiver) init() {
	heap.Init(&r.fragments)
}

func (r *receiver) getAck() uint32 {
	r.m.Lock()
	defer r.m.Unlock()
	return uint32(r.ackNo)
}

/* Processes window into buffer stream if the ordered fragments are ready (in order).
Precondition: r.m mutex is held. */
func (r *receiver) processIntoBuffer() {
	for r.fragments.Len() > 0 {
		frag := heap.Pop(&(r.fragments)).(*pqItem)

		if r.windowStart != frag.priority {
			// This packet cannot be added to the buffer yet.
			logrus.Debug("WINDOW START: ", r.windowStart, " FRAG PRIORITY: ", frag.priority)
			if frag.priority > r.windowStart {
				heap.Push(&r.fragments, frag)
				break
			}
		} else if frag.FIN {
			r.windowStart++
			r.ackNo++
			r.closedCond.L.Lock()
			logrus.Debug("RECEIVING FIN PACKET")
			r.closed = true
			r.closedCond.Signal()
			r.closedCond.L.Unlock()
			break
		} else {
			r.buffer.Write(frag.value)
			r.windowStart++
			r.ackNo++
		}
	}
	r.bufferCond.Signal()
}

func (r *receiver) read(buf []byte) (int, error) {
	r.bufferCond.L.Lock()
	for {
		r.m.Lock()
		logrus.Debug("BUFFER LEN: ", r.buffer.Len(), " buf len: ", len(buf), "closed? ", r.closed)
		if r.buffer.Len() >= len(buf) || r.closed {
			break
		}
		r.m.Unlock()
		r.bufferCond.Wait()

	}
	defer r.m.Unlock()
	defer r.bufferCond.L.Unlock()

	nbytes, err := r.buffer.Read(buf)
	if err == nil && r.closed {
		err = io.EOF
	}
	return nbytes, err
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

/* Utility function to add offsets so that we eliminate wraparounds.
   Precondition: must be holding frame number */
func (r *receiver) unwrapFrameNo(frameNo uint32) uint64 {
	// The previous, offsets are represented by the 32 least significant bytes of the window start.
	windowStart := r.windowStart
	newNo := uint64(frameNo) + windowStart - uint64(uint32(windowStart))

	// Add an additional offset for the case in which seqNo has wrapped around again.
	if frameNo < uint32(windowStart) {
		newNo += 1 << 32
	}
	return newNo
}

/* Precondition: receive window lock is held. */
func (r *receiver) receive(p *frame) error {
	r.m.Lock()
	defer r.m.Unlock()
	windowStart := r.windowStart
	windowEnd := r.windowStart + uint64(uint32(r.windowSize))

	frameNo := r.unwrapFrameNo(p.frameNo)
	logrus.Debug("receive frame frameNo: ", frameNo, " ackNo: ", p.ackNo, " data: ", string(p.data), " FIN? ", p.flags.FIN, " recv ack no? ", r.ackNo)
	if !frameInBounds(windowStart, windowEnd, frameNo) {
		logrus.Debug("received dataframe out of receive window bounds")
		return errors.New("received dataframe out of receive window bounds")
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
