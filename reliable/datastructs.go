package main

import (
	"container/heap"
)

type RTQueue struct {
	frames []([]byte)
	count uint32
}

func (rtq *RTQueue) Push(frame []byte) {
	rtq.frames = append(rtq.frames, frame)
	rtq.count++
}

func (rtq *RTQueue) Pop() {
	if rtq.count > 0 {
		rtq.frames = rtq.frames[1:]
		rtq.count--
	}
}

func (rtq *RTQueue) Ack(ack uint32) {
	for rtq.count > 0 && uint32(getCtr(rtq.frames[0])) <= ack {
		rtq.Pop()
	}
}

type Item struct {
	value    []byte
	priority uint32
	index int
}

// A PriorityQueue implements heap.Interface and holds Items.
type PriorityQueue []*Item

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	return pq[i].priority < pq[j].priority
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *PriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*Item)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

type Window struct {
	ctrs map[uint32]bool
	pq PriorityQueue
	maxsz int
	currsz int
}

func (w *Window) init(maxsz int) {
	w.maxsz = maxsz
	w.currsz = 0
	w.ctrs = make(map[uint32]bool)
	w.pq = make(PriorityQueue, 0)
	heap.Init(&w.pq)
}

func (w *Window) hasCtr(ctr uint32) bool {
	return w.ctrs[ctr]
}

func (w *Window) getCurrSz() int {
	return w.currsz
}

func (w *Window) getMaxSz() int {
	return w.maxsz
}

func (w *Window) push(frame []byte) bool {
	if w.currsz < w.maxsz {
		ctr := getCtr(frame)
		w.ctrs[ctr] = true
		heap.Push(&w.pq, &Item{value: frame, priority: ctr})
		w.currsz += getDataSz(frame)
		return true
	}
	return false
}

func (w *Window) hasNextFrame(lastacked uint32) bool{
	return w.len() > 0 && w.pq[0].priority == lastacked + 1
}

func (w *Window) pop() []byte {
	item := heap.Pop(&w.pq).(*Item)
	delete(w.ctrs, item.priority)
	w.currsz -= getDataSz(item.value)
	return item.value
}

func (w *Window) len() int {
	return w.pq.Len()
}
