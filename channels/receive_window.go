package channels

import (
	"bytes"
	"container/heap"
	"errors"
	"sync"

	"github.com/sirupsen/logrus"
)

type ReceiveWindow struct {
	buffer     *bytes.Buffer
	bufferCond sync.Cond
	closed     bool
	fragments  PriorityQueue
	m          sync.Mutex
	maxSize    uint16
	/*
		We treat the sequence numbers as uint64 so we can avoid wraparounds
		and not have to update our priority queue orderings in the case of a
		wraparound.
	*/
	ackNo       uint64
	windowStart uint64
}

func (r *ReceiveWindow) init() {
	heap.Init(&r.fragments)
}

/* Processes window into buffer stream if the ordered fragments are ready (in order).
Precondition: receive window mutex is held. */
func (r *ReceiveWindow) processIntoBuffer() {
	for r.fragments.Len() > 0 {
		frag := heap.Pop(&(r.fragments)).(*Item)
		if frag.FIN {
			r.windowStart += 1
			r.ackNo += 1
			r.closed = true
			break
		}
		if r.windowStart != frag.priority {
			heap.Push(&r.fragments, frag)
			break
		} else {
			r.buffer.Write(frag.value)
			r.windowStart += 1
			r.ackNo += 1
		}
	}
	r.bufferCond.Signal()
}

func (r *ReceiveWindow) read(buf []byte) (int, error) {
	r.bufferCond.L.Lock()
	for {
		r.m.Lock()
		if r.buffer.Len() >= len(buf) || r.closed {
			break
		}
		r.m.Unlock()
		r.bufferCond.Wait()

	}
	defer r.m.Unlock()
	defer r.bufferCond.L.Unlock()

	return r.buffer.Read(buf)
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

/* Utiltiy function to add offsets so that we eliminate wraparounds.
   Precondition: must be holding frame number */
func (r *ReceiveWindow) unwrapFrameNo(frameNo uint32) uint64 {
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
func (r *ReceiveWindow) receive(p *Packet) error {
	r.m.Lock()
	defer r.m.Unlock()
	windowStart := r.windowStart
	windowEnd := r.windowStart + uint64(uint32(r.maxSize))

	frameNo := r.unwrapFrameNo(p.frameNo)
	logrus.Info("receive frame ", windowStart, windowEnd, frameNo, p.ackNo, p.data, r.ackNo, p.flags.FIN)
	if !frameInBounds(windowStart, windowEnd, frameNo) {
		logrus.Info("received dataframe out of receive window bounds")
		return errors.New("received dataframe out of receive window bounds")
	}

	if p.dataLength > 0 || p.flags.FIN {
		heap.Push(&r.fragments, &Item{
			value:    p.data,
			priority: frameNo,
			FIN:      p.flags.FIN,
		})
	}

	r.processIntoBuffer()

	return nil
}
