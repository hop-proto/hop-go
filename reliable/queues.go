package main

import (
	"container/heap"
)

type RTQueue struct {
	frames [](*[]byte)
	count int
}

func (rtq *RTQueue) Push(frame *[]byte) {
	rtq.frames = append(rtq.frames, frame)
	rtq.count++
}

func (rtq *RTQueue) Pop() {
	if rtq.count > 0 {
		rtq.frames = rtq.frames[1:]
		rtq.count--
	}
}

func (rtq *RTQueue) Ack(ack int) {
	for rtq.count > 0 && getCID(*(rtq.frames[0])) <= ack {
		rtq.Pop()
	}
}

type Item struct {
	value    []byte
	priority int
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
	pq PriorityQueue
	maxsz int
}

func (w *Window) init(maxsz int) {
	w.maxsz = maxsz
	w.pq = make(PriorityQueue, 0)
	heap.Init(&w.pq)
}

func (w *Window) push(frame []byte) bool {
	if w.len() < w.maxsz {
		heap.Push(&w.pq, &Item{value: frame, priority: int(frame[0])})
		return true
	}
	return false
}

func (w *Window) pop() ([]byte, bool) {
	if w.len() > 0 {
		item := heap.Pop(&w.pq).(*Item)
		return item.value, true
	}
	return []byte{}, false
}

func (w *Window) len() int {
	return w.pq.Len()
}
