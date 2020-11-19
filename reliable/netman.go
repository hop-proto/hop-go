package main

import (
	"fmt"
	"sync"
)

type recvfn (func() (int, []byte, bool))
type sendfn func([]byte)
type closefn func()

type NetworkManager struct {
	wg sync.WaitGroup
	sendCh chan []byte
	close closefn
	MAX_FRAME_SIZE int
}

func (nm *NetworkManager) start(recv recvfn, send sendfn, close closefn,
	MAX_FRAME_SIZE int) {

	nm.MAX_FRAME_SIZE = MAX_FRAME_SIZE
	nm.sendCh = make(chan []byte)
	nm.close = close
	nm.wg.Add(1)
	go nm.senderThread(send)
	nm.wg.Add(1)
	go nm.receiverThread(recv)
}

func (nm *NetworkManager) senderThread(send sendfn) {
	defer nm.wg.Done()
	for frame := range nm.sendCh {
		fmt.Println("Sending", frame)
		send(frame)
	}
	fmt.Println("Sender Closing")
}

func (nm *NetworkManager) receiverThread(recv recvfn) {
	defer nm.wg.Done()
	for {
		n, frame, closed := recv()
		if closed {
			fmt.Println("Receiver Closing")
			return
		}
		fmt.Println("Receiving", n, frame[0:n])
		//nm.send([]byte{4,3,2,1})
		//time.Sleep(time.Second)
	}
}

func (nm *NetworkManager) shutdown() {
	close(nm.sendCh)
	nm.close()
	nm.wg.Wait()
}

func (nm *NetworkManager) send(buf []byte) {
	nm.sendCh <- buf
}
