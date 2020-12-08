package main

import (
	"os"
	"fmt"
	"net"
	//"time"
	//"sync"
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

	fmt.Println("Starting ChannelApp")
	ca := ChannelApp{}
	ca.Init(conn, saddr, MAX_FRAME_SIZE)
	ca.Start()
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error ", err.Error())
		os.Exit(1)
	}
}
