package channels

import (
	"container/heap"
	"errors"
	"sync"

	"github.com/sirupsen/logrus"
)

type ReceiveWindow struct {
	m         sync.Mutex
	fragments PriorityQueue
	maxSize   uint16
	curSize   uint16
	/*
		We treat the sequence numbers as uint64 so we can avoid wraparounds
		and not have to update our priority queue orderings in the case of a
		wraparound.
	*/
	windowStart uint64
	ackNo       uint64
}

func (r *ReceiveWindow) init() {
	heap.Init(&r.fragments)
	r.curSize = 0
}

func (r *ReceiveWindow) read(buf []byte) (int, error) {

	r.m.Lock()
	defer r.m.Unlock()
	bytesRead := 0
	bufLen := len(buf)

	for bytesRead <= bufLen && r.fragments.Len() > 0 {
		frag := heap.Pop(&(r.fragments)).(*Item)
		fragStart := frag.priority
		fragEnd := fragStart + uint64(len(frag.value))
		if fragStart <= r.windowStart && fragEnd >= r.windowStart {
			startIdx := r.windowStart - fragStart
			numCopied := copy(buf[bytesRead:], frag.value[startIdx:])
			r.windowStart += uint64(numCopied)
			bytesRead += numCopied
			if fragStart+uint64(numCopied) < fragEnd {
				r.fragments.Push(&Item{
					value:    frag.value[startIdx+uint64(numCopied):],
					priority: r.windowStart,
				})
			}
		}
	}
	// logrus.Info("In read: bytesread: ", bytesRead, " bufLen: ", bufLen, " fraglen: ", r.fragments.Len())
	return bytesRead, nil
}

/* Checks if frame is in bounds of receive window. */
func frameInBounds(wS uint64, wE uint64, fS uint64, fE uint64) bool {
	if wS < wE { // contiguous:  ------WS+++++++WE------
		if fE > wE || fS > wE || fE < wS || fS < wS {
			return false
		}
	} else { // wraparound: ++++WE------WS++++
		if (fE > wE && fE < wS) || (fS > wE && fS < wS) {
			return false
		}
	}
	return true
}

/* Utiltiy function to add offsets so that we eliminate wraparounds.
   Precondition: must be holding sequence nnumber */
func (r *ReceiveWindow) unwrapSequenceNumber(seqNo uint32) uint64 {
	// The previous, offsets are represented by the 32 least significant bytes of the window start.
	windowStart := r.windowStart
	newNo := uint64(seqNo) + windowStart - uint64(uint32(windowStart))

	// Add an additional offset for the case in which seqNo has wrapped around again.
	if seqNo < uint32(windowStart) {
		newNo += 1 << 32
	}
	return newNo
}

func (r *ReceiveWindow) receive(p *Packet) error {
	r.m.Lock()
	defer r.m.Unlock()
	windowStart := r.windowStart
	windowEnd := r.windowStart + uint64(uint32(r.maxSize))

	frameStart := r.unwrapSequenceNumber(p.frameNo)
	frameEnd := frameStart + uint64(uint32(len(p.data)))
	if !frameInBounds(windowStart, windowEnd, frameStart, frameEnd) {
		// logrus.Info("received dataframe out of receive window bounds", "Receive: ackNo: ", r.ackNo, " fraglen: ", r.fragments.Len(), " window: ", windowStart, " ", windowEnd, " data:", p.data)
		return errors.New("received dataframe out of receive window bounds")
	}
	if len(p.data) > 0 {
		r.fragments.Push(&Item{
			value:    p.data,
			priority: frameStart,
		})
	}

	// Update ack number, if necessary.
	if frameStart <= r.ackNo && frameEnd >= r.ackNo {
		r.ackNo = frameEnd
	}
	logrus.Debug("Receive: ackNo: ", r.ackNo, " fraglen: ", r.fragments.Len(), " window: ", windowStart, " ", windowEnd, " data:", p.data, "framestart: ", frameStart)
	return nil
}

func (r *ReceiveWindow) getAck() uint32 {
	return uint32(r.ackNo)
}
