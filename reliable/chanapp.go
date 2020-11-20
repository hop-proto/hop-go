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
	channelChs [](chan []byte)

	nrecv recvfn // Network recv 
	nsend sendfn // Network send 
	nclose closefn // Network close 

	MAX_FRAME_SIZE int
	MAX_SEND_BUF_SIZE int
}

func (ca *ChanApp) init(nrecv recvfn, nsend sendfn, nclose closefn,
	MAX_FRAME_SIZE int, MAX_SEND_BUF_SIZE int) {

	ca.MAX_FRAME_SIZE = MAX_FRAME_SIZE
	ca.MAX_SEND_BUF_SIZE = MAX_SEND_BUF_SIZE

	ca.nrecv = nrecv
	ca.nsend = nsend
	ca.nclose = nclose

	ca.sendCh = make(chan []byte)
	ca.channelChs = make([](chan []byte), 256)
	for i:= 0; i < len(ca.channelChs); i++ {
		ca.channelChs[i] = make(chan []byte, 64)
	}
}

func (ca *ChanApp) start() {
	ca.wg.Add(1)
	go ca.senderThread()
	ca.wg.Add(1)
	go ca.receiverThread()
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
		fmt.Println("Receiving", frame)
		fmt.Println("IsReq", isReq(frame))
		fmt.Println("IsRep", isRep(frame))
		fmt.Println("IsData", isData(frame))
		if isRep(frame) || isData(frame) {
			ca.routeFrame(frame)
		} else { // Req Frame
			fmt.Println("Request Recv")
		}
	}
}

func (ca *ChanApp) shutdown() {
	close(ca.sendCh)
	for _, ch := range ca.channelChs {
		close(ch)
	}
	ca.nclose()
	ca.wg.Wait()
}

func (ca *ChanApp) send(buf []byte) {
	ca.sendCh <- buf
}

func (ca *ChanApp) routeFrame(frame []byte) {
	fmt.Println("Routing", frame, "to Channel", getCID(frame))
	// nonblocking best effort
	select {
		case ca.channelChs[getCID(frame)] <- frame:
			return
		default:
			return
	}
}
