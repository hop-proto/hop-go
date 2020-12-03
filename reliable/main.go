package main

import (
	"os"
	"fmt"
	"net"
	"time"
	"sync"
	"strconv"
)

var MAX_FRAME_SIZE = 512
var MAX_SEND_BUF_SIZE = 64
var MAX_WINDOW_SIZE = 1024
var LHOST = net.ParseIP("127.0.0.1")

func main() {
	port, err := strconv.Atoi(os.Args[2])
	checkError(err)
	caddr := &net.UDPAddr{IP: LHOST, Port: port}

	port, err = strconv.Atoi(os.Args[3])
	checkError(err)
	saddr := &net.UDPAddr{IP: LHOST, Port: port}

	conn, err := net.ListenUDP("udp", caddr)

	recv := func() (int, []byte, bool) {
		var buf = make([]byte, MAX_FRAME_SIZE)
		n, _, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			return 0, []byte{}, true
		} else {
			return n, buf, false
		}
	}

	send := func(buf []byte) {
		conn.WriteToUDP(buf, saddr)
	}
	close := func() {
		conn.Close()
	}

	ca := ChanApp{}
	ca.init(recv, send, close, MAX_FRAME_SIZE, MAX_SEND_BUF_SIZE, MAX_WINDOW_SIZE)
	ca.start()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10*time.Second)
		ca.shutdown()
	}()
	wg.Add(1)
	go func(){
		defer wg.Done()
		for i := 0; i<256; i++{
			data, ok := ca.readCh(0)
			if !ok {
				break
			}
			fmt.Println("Reading", data)
		}
	}()

	if os.Args[1] == "c" {
		ca.send([]byte{1, 0x83 ,0,0,  0,0,0,0,  0,0,0,5, 11, 12, 13, 14, 15}) // Req
		ca.send([]byte{2, 0x48 ,0,0,  0,0,0,0,  0,0,0,5, 11, 12, 13, 14, 15}) // Rep
		ca.send([]byte{0,0,0,5,  0,0,0,0,  0,0,0,5, 11, 12, 13, 14, 15}) // Data
		ca.send([]byte{0,0,0,2,  0,0,0,0,  0,0,0,2, 2, 3}) // Data
		ca.send([]byte{0,0,0,4,  0,0,0,0,  0,0,0,4, 7, 8, 9, 10}) // Data
		ca.send([]byte{0,0,0,3,  0,0,0,0,  0,0,0,3, 4, 5, 6}) // Data
		ca.send([]byte{0,0,0,1,  0,0,0,0,  0,0,0,1, 1}) // Data
		ca.send([]byte{0,0,0,5,  0,0,0,0,  0,0,0,5, 11, 12, 13, 14, 15}) // Data
		ca.send([]byte{0,0,0,2,  0,0,0,0,  0,0,0,2, 2, 3}) // Data
		ca.send([]byte{0,0,0,4,  0,0,0,0,  0,0,0,4, 7, 8, 9, 10}) // Data
		ca.send([]byte{0,0,0,3,  0,0,0,0,  0,0,0,3, 4, 5, 6}) // Data
		ca.send([]byte{0,0,0,1,  0,0,0,0,  0,0,0,1, 1}) // Data
	}
	wg.Wait()
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error ", err.Error())
		os.Exit(1)
	}
}
