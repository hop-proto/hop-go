package channels

import "container/heap"

type ReceiveWindow struct {
	fragments PriorityQueue
	stream    chan byte
	maxSize   uint16
	curSize   uint16
	seqNo     uint32
}

func (r *ReceiveWindow) Init() {
	heap.Init(&r.fragments)
	r.curSize = 0
}

func (r *ReceiveWindow) Read(buf []byte) uint32 {
	// TODO: Consider primitives that could speed this up.
	bytesRead := uint32(0)
	for len(r.stream) > 0 && int(bytesRead) < len(buf) {
		b := <-r.stream
		buf[bytesRead] = b
		bytesRead += 1
		r.seqNo += 1
	}
	return bytesRead
}

func (r *ReceiveWindow) Receive(p *Packet) {

	windowEnd := p.frameNo + uint32(len(p.data))

	var size = 0

	// If windowEnd < seqNo, then there is wraparound.
	if windowEnd < r.seqNo {
		size
	}
	r.fragments.Push(&Item{
		value:    p.data,
		priority: p.frameNo,
	})
}

func (r *ReceiveWindow) GetAck() uint32 {
	// TODO: Perform heap.peek(), get seqNo + len([]byte) + 1
	return 0
}
