package main

import (
	"fmt"
	"sync"
	"time"
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
	channelConds   [256](*sync.Cond)
	channelTimers  [256]int32

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

	for i:= 0; i < len(ca.channelConds); i++ {
		ca.channelConds[i] = &sync.Cond{L: &sync.Mutex{}}
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
		ca.wg.Add(1)
		go ca.channelTimerThread(i)
	}
}

func (ca *ChanApp) senderThread() {
	defer ca.wg.Done()
	for frame := range ca.sendCh {
		fmt.Println("Sending", frame)
		ca.nsend(frame)
	}
	fmt.Println("Channel Sender Closing")
}

func (ca *ChanApp) receiverThread() {
	defer ca.wg.Done()
	for {
		n, buf, closed := ca.nrecv()
		if closed {
			fmt.Println("Chan App Receiver Closing")
			return
		}
		frame := buf[:n]
		if isRep(frame) || isData(frame) {
			ca.routeFrame(frame)
		} else { // Req Frame
			fmt.Println("Channel", getCID(frame), "received request frame")
		}
	}
}

func (ca *ChanApp) channelRecvThread(cid int){
	defer ca.wg.Done()
	var lastAcked uint32 = 0
	for frame := range ca.channelRecvChs[cid] {
		if getCtr(frame) <= lastAcked || ca.channelWindows[cid].hasCtr(getCtr(frame)){
			fmt.Println("Channel", cid, "already Seen Frame", getCtr(frame))
			continue
		}
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
			updateAck(&ca.channelAcks[cid], lastAcked)
			ca.channelConds[cid].Signal()
			fmt.Println("Last Acked:", lastAcked)
		}
	}
	fmt.Println("Channel Recv Thread Closing: ", cid)
}

func (ca *ChanApp) channelTimerThread(cid int) {
	defer ca.wg.Done()
	for {
		timer := readTimer(&ca.channelTimers[cid])
		if timer < 0 {
			fmt.Println("Channel Timer", cid, "Closing")
			break
		}
		time.Sleep(50 * time.Millisecond)
		if timer < 250 {
			addTimer(&ca.channelTimers[cid], 50)
		}
		ca.channelConds[cid].Signal()
	}
}

func (ca *ChanApp) channelSendThread(cid int, windowsz int) {
	defer ca.wg.Done()
	// When do we want to close this thread?
	// what is the exit condition to call "return"
	// need to update Window sz to be byte limit
	//var ctr uint32 = 1 // is this right?
	//recvWindowSz := windowsz
	for {
		if len(ca.channelSendChs) ==  0 {
			ca.channelConds[cid].Wait()
		}
/*
		sentAcks = false

		latestAck = load atomic ack
		Update RT queue {
			pop nodes <= latestAck and record how many bytes Acked
			latestAck = load atomic ack
			send RTO with latestAck in ack field and ctr = priority
				sentAcks = true
		}
		
		recWindowSz -= bytes Acked
		for windowsz > 0 {
			latestAck = load atomic ack
			// nonblocking
			if data <- ch {
				send data frame with latestAck in ack field and ctr++
					sentAcks = true
				add data frame to RTqueue
				windowsz -= datasz
			}
		}
		if !sentAcks {
			latestAck = load atomic ack
			send empty data frame with latestAck and ctr++
			add data frame to RTqueue
		}
*/
	}
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
	for i := 0; i < len(ca.channelConds); i++ {
		ca.channelConds[i].Signal()
	}
	for i := 0; i < len(ca.channelTimers); i++ {
		updateTimer(&ca.channelTimers[i], -100)
	}
	ca.nclose()
	ca.wg.Wait()
	for i := 0; i < len(ca.channelConds); i++ {
		ca.channelConds[i] = nil
	}
}

func (ca *ChanApp) readCh(cid int) ([]byte, bool) {
	// should change this later to byte reading...
	data, ok := <-ca.channelReadChs[cid]
	if ok {
		return data, true
	}
	return []byte{}, false
}

func (ca *ChanApp) writeCh(cid int, buf []byte) {
	// should change this later to byte writing ...
	ca.channelSendChs[cid] <- buf
	ca.channelConds[cid].Signal()
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
