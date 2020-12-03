package main

import (
	"fmt"
	"sync"
)

type recvfn (func() (int, []byte, bool))
type sendfn func([]byte)
type closefn func()

type ChanApp struct {
	wg sync.WaitGroup

	sendCh chan []byte
	channelRecvChs [256](chan []byte)
	channelWindows [256](Window)
	channelReadChs [256](chan []byte)
	channelSendChs [256](chan []byte)
	channelAcks    [256]uint32

	nrecv recvfn // Network recv 
	nsend sendfn // Network send 
	nclose closefn // Network close 

	MAX_FRAME_SIZE int
	MAX_SEND_BUF_SIZE int
	MAX_WINDOW_SIZE int
}

func (ca *ChanApp) init(nrecv recvfn, nsend sendfn, nclose closefn,
	MAX_FRAME_SIZE int, MAX_SEND_BUF_SIZE int, MAX_WINDOW_SIZE int) {

	ca.MAX_FRAME_SIZE = MAX_FRAME_SIZE
	ca.MAX_SEND_BUF_SIZE = MAX_SEND_BUF_SIZE
	ca.MAX_WINDOW_SIZE = MAX_WINDOW_SIZE

	ca.nrecv = nrecv
	ca.nsend = nsend
	ca.nclose = nclose

	ca.sendCh = make(chan []byte, MAX_SEND_BUF_SIZE)

	for i:= 0; i < len(ca.channelRecvChs); i++ {
		ca.channelRecvChs[i] = make(chan []byte, 64)
	}
	for i:= 0; i < len(ca.channelReadChs); i++ {
		ca.channelReadChs[i] = make(chan []byte, 64)
	}
	for i:= 0; i < len(ca.channelSendChs); i++ {
		ca.channelSendChs[i] = make(chan []byte, 64)
	}
	for i:= 0; i < len(ca.channelWindows); i++ {
		ca.channelWindows[i].init(MAX_WINDOW_SIZE)
	}

}

func (ca *ChanApp) start() {
	ca.wg.Add(1)
	go ca.senderThread()
	ca.wg.Add(1)
	go ca.receiverThread()
	for i:= 0; i < 4; i++ {
		ca.wg.Add(1)
		go ca.channelRecvThread(i)
	}
}

func (ca *ChanApp) senderThread() {
	defer ca.wg.Done()
	for frame := range ca.sendCh {
		fmt.Println("Sending", frame)
		ca.nsend(frame)
	}
	fmt.Println("Sender Closing")
}

func (ca *ChanApp) receiverThread() {
	defer ca.wg.Done()
	for {
		n, buf, closed := ca.nrecv()
		if closed {
			fmt.Println("Receiver Closing")
			return
		}
		frame := buf[:n]
		if isRep(frame) || isData(frame) {
			ca.routeFrame(frame)
		} else { // Req Frame
			fmt.Println("Request Recv")
		}
	}
}

func (ca *ChanApp) channelRecvThread(cid int){
	defer ca.wg.Done()
	var lastAcked uint32 = 0
	for frame := range ca.channelRecvChs[cid] {
		if isRep(frame) {
			fmt.Println("Channel ", cid, " received rep frame.")
		} else {
			fmt.Println("Channel", cid, "received data frame", getCtr(frame))
			pushed := ca.channelWindows[cid].push(frame)
			if !pushed {
				continue
			}
			for ca.channelWindows[cid].hasNextframe(lastAcked) &&
				len(ca.channelReadChs[cid]) < 64 {
				popframe := ca.channelWindows[cid].pop()
				lastAcked++
				fmt.Println("Data", getData(popframe))
				ca.channelReadChs[cid] <- getData(popframe)
			}
			// should we signal a cond variable?
			// sender thread can wake up and send Ack
			// if not outgoing data is queued
			updateAck(&ca.channelAcks[cid], lastAcked)
			fmt.Println("Last Acked:", lastAcked)
		}
	}
	fmt.Println("Channel Recv Thread Closing: ", cid)
}

/*
has access to an atomic Ack and atomic timer, RT queue
we need a thread that updates timer every 50 ms
*/
func (ca *ChanApp) channelSendThread(cid int) {
	defer ca.wg.Done()
}

func (ca *ChanApp) shutdown() {
	close(ca.sendCh)
	for _, ch := range ca.channelRecvChs {
		close(ch)
	}
	for _, ch := range ca.channelReadChs {
		close(ch)
	}
	for _, ch := range ca.channelSendChs {
		close(ch)
	}
	ca.nclose()
	ca.wg.Wait()
}

func (ca *ChanApp) readCh(cid int) ([]byte, bool) {
	data, ok := <-ca.channelReadChs[cid]
	if ok {
		return data, true
	}
	return []byte{}, false
}

func (ca *ChanApp) writeCh(cid int, buf []byte) {
	ca.channelSendChs[cid] <- buf:
}

func (ca *ChanApp) send(buf []byte) {
	// nonblocking best effort
	select {
		case ca.sendCh <- buf:
			return
		default:
			return
	}
	ca.sendCh <- buf
}

func (ca *ChanApp) routeFrame(frame []byte) {
	fmt.Println("Routing", frame, "to Channel", getCID(frame))
	// nonblocking best effort
	select {
		case ca.channelRecvChs[getCID(frame)] <- frame:
			return
		default:
			return
	}
}
