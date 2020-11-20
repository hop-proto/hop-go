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
	ca.init(recv, send, close, MAX_FRAME_SIZE, MAX_SEND_BUF_SIZE)
	ca.start()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10*time.Second)
		ca.shutdown()
	}()

	if os.Args[1] == "c" {
		buf := make([]byte, MAX_FRAME_SIZE)
		lol := []byte{1,0x83,3,4} // Req
		copy(buf, lol)
		ca.send(buf[:len(lol)])
		ca.send([]byte{1, 0x4B}) // Rep
		ca.send([]byte{1, 0xB}) // Data
	}
	wg.Wait()
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error ", err.Error())
		os.Exit(1)
	}
}
