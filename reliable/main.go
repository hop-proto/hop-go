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

func main() {
	port, err := strconv.Atoi(os.Args[3])
	checkError(err)
	caddr := &net.UDPAddr{IP: net.ParseIP(os.Args[2]), Port: port}

	port, err = strconv.Atoi(os.Args[5])
	checkError(err)
	saddr := &net.UDPAddr{IP: net.ParseIP(os.Args[4]), Port: port}

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
	nm := NetworkManager{}
	nm.start(recv, send, close, MAX_FRAME_SIZE)
	ca := ChannelApp{}
	ca.start(&nm)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10*time.Second)
		ca.shutdown()
	}()

	if os.Args[1] == "c" {
		buf := make([]byte, MAX_FRAME_SIZE)
		lol := []byte{1,2,3,4}
		copy(buf, lol)
		ca.nm.send(buf[:len(lol)])
	}
	wg.Wait()
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error ", err.Error())
		os.Exit(1)
	}
}
