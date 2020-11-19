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
}

func (n *NetworkManager) init(recv recvfn, send sendfn, close closefn) {
	n.sendCh = make(chan []byte)
	n.close = close
	n.wg.Add(1)
	go func(){
		defer n.wg.Done()
		for {
			n, frame, closed := recv()
			if closed {
				fmt.Println("Receiver Closing")
				return
			}
			fmt.Println(n, frame)
		}
	}()
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for frame := range n.sendCh {
			fmt.Println(frame)
			send(frame)
		}
		fmt.Println("Sender Closing")
	} ()
}

func (n *NetworkManager) shutdown() {
	close(n.sendCh)
	n.close()
	n.wg.Wait()
}
