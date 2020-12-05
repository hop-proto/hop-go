package main

import (
	"net"
)

var SEND_BUF_SIZE = 64
var WINDOW_SIZE = 4096

type ChannelApp struct {
	ca *ChanApp
}

func (ca *ChannelApp) Init(conn net.PacketConn, raddr net.Addr, maxFrSz int){
	recv := func() (int, []byte, bool) {
		var buf = make([]byte, maxFrSz)
		n, _, err := conn.ReadFrom(buf[0:])
		if err != nil {
			return 0, []byte{}, true
		}
		return n, buf, false
	}
	send := func(buf []byte) {
		conn.WriteTo(buf, raddr)
	}
	close := func() {
		conn.Close()
	}
	internal_ca := &ChanApp{}
	internal_ca.init(recv, send, close, maxFrSz, SEND_BUF_SIZE, WINDOW_SIZE)
	ca.ca = internal_ca
}

func (ca *ChannelApp) Start() {
	ca.ca.start()
}

func (ca *ChannelApp) Shutdown() {
	ca.ca.shutdown()
}

func (ca *ChannelApp) listenChan() *Channel {
	return &Channel{}
}
