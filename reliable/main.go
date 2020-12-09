package main

import (
	"os"
	"fmt"
	"net"
	"time"
	"sync"
	"strconv"
)

var MAX_FRAME_SIZE = 1024
var LHOST = net.ParseIP("127.0.0.1")

func main() {
	port, err := strconv.Atoi(os.Args[2])
	checkError(err)
	caddr := &net.UDPAddr{IP: LHOST, Port: port}

	port, err = strconv.Atoi(os.Args[3])
	checkError(err)
	saddr := &net.UDPAddr{IP: LHOST, Port: port}

	conn, err := net.ListenUDP("udp", caddr)
	// conn, err = SSTP.ListenSSTP(...)

	fmt.Println("Starting ChannelApp")
	ca := ChannelApp{}
	ca.Init(conn, saddr, MAX_FRAME_SIZE)
	ca.Start()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(10*time.Second)
		ca.Shutdown()
	}()
	wg.Add(1)
	go func(){
		defer wg.Done()
		for i := 0; i<256; i++{
			var buf = make([]byte, 1024)
			ch0 := &Channel{ca: ca.ca}
			ch0.SetDeadline(time.Now())
			n, err := ch0.Read(buf)
			if err != nil {
				fmt.Println(err.Error())
				break
			}
			fmt.Println("Reading", buf[:n])
		}
	}()

	if os.Args[1] == "c" {
		ca.ca.send([]byte{1, 0x83 ,0,0,  0,0,0,0,  0,0,0,5, 11, 12, 13, 14, 15}) // Req
		ca.ca.send([]byte{2, 0x48 ,0,0,  0,0,0,0,  0,0,0,5, 11, 12, 13, 14, 15}) // Rep
		ca.ca.send([]byte{0,0,0,5,  0,0,0,0,  0,0,0,5, 11, 12, 13, 14, 15}) // Data
		ca.ca.send([]byte{0,0,0,2,  0,0,0,0,  0,0,0,2, 2, 3}) // Data
		ca.ca.send([]byte{0,0,0,4,  0,0,0,0,  0,0,0,4, 7, 8, 9, 10}) // Data
		ca.ca.send([]byte{0,0,0,3,  0,0,0,0,  0,0,0,3, 4, 5, 6}) // Data
		ca.ca.send([]byte{0,0,0,1,  0,0,0,0,  0,0,0,1, 1}) // Data
		ca.ca.send([]byte{0,0,0,5,  0,0,0,0,  0,0,0,5, 11, 12, 13, 14, 15}) // Data
		ca.ca.send([]byte{0,0,0,2,  0,0,0,0,  0,0,0,2, 2, 3}) // Data
		ca.ca.send([]byte{0,0,0,4,  0,0,0,0,  0,0,0,4, 7, 8, 9, 10}) // Data
		ca.ca.send([]byte{0,0,0,3,  0,0,0,0,  0,0,0,3, 4, 5, 6}) // Data
		ca.ca.send([]byte{0,0,0,1,  0,0,0,0,  0,0,0,1, 1}) // Data
	}
	wg.Wait()
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error ", err.Error())
		os.Exit(1)
	}
}
