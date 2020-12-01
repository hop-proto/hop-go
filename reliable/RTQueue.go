package main

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

