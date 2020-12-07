package main

import (
	"net"
	"sync"
)

// Network Send Buffer Size in Frames
var SEND_BUF_SIZE = 64
// Window Size in Bytes
var WINDOW_SIZE = 4096

type ChannelApp struct {
	// Internal Channel Application
	ca *chanApp
}

/*
conn: Tunnel Conn
raddr: Provided by Conn (needed for Packet.Conn write(...))
maxFrSz: Max frame size of tunnel connection
*/
func (ca *ChannelApp) Init(conn net.PacketConn, raddr net.Addr, maxFrSz int) {
	// Network Recv Function
	nrecv := func() (int, []byte, error) {
		var frame = make([]byte, maxFrSz)
		n, _, err := conn.ReadFrom(frame[0:])
		if err != nil {
			return 0, []byte{}, err
		}
		return n, frame, nil
	}
	// Network Send Function
	// Best Effort Send (ignores errors)
	nsend := func(frame []byte) { conn.WriteTo(frame, raddr) }
	// Network Close Function
	nclose := func() { conn.Close() }

	internal_ca := &chanApp{}
	internal_ca.init(nrecv, nsend, nclose, maxFrSz, SEND_BUF_SIZE, WINDOW_SIZE)
	ca.ca = internal_ca
}

func (ca *ChannelApp) Start() {
	ca.ca.start()
}

func (ca *ChannelApp) Shutdown() {
	ca.ca.shutdown()
	// For garbage collection
	ca.ca = nil
}

func (ca *ChannelApp) Listener() *ChannelListener {
	return &ChannelListener{ca: ca.ca}
}

// Implements net.Listener
type ChannelListener struct {
	// Internal Channel Application
	ca *chanApp
	// Operation Lock
	mu sync.Mutex
}

func (cl *ChannelListener) Accept() (*Channel, error) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return &Channel{}, nil
}

func (cl *ChannelListener) Close() error {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.ca = nil
	return nil
}

type CALAddr struct {}

func (cal *CALAddr) Network() string {
	return "ChanApp"
}

func (cal *CALAddr) String() string {
	return "()"
}

func (cl *ChannelListener) Addr() net.Addr {
	return &CALAddr{}
}

type nrecvfn (func() (int, []byte, error))
type nsendfn func([]byte)
type nclosefn func()

type chanApp struct {
	wg sync.WaitGroup

	// Go Channel used internally to send frames
	nsendCh chan []byte

	// Go Channels used internally for routing frames
	// to channels.
	channelRecvChs [256](chan []byte)

	// Channel windows
	// channelWindows [256]window

	// Channel Tickers used for clock ticks
	channelTickers [256](*time.Ticker)

	// Go Channels used internally to route contiguous
	// data sections to channel.read() calls
	channelReadChs [256](chan []byte)

	// Go Channels used internally to route data
	// to be sent from channel.write() calls
	channelWriteChs [256](chan []byte)

	// Go Channels used internally to signal
	// read/write calls that channel
	// has closed.
	// close(channelCloseRW[cid]) will
	// unblock all <-channelCloseRW[cid]
	channelCloseRW [256](chan struct{})

	// Latest Ack used as an Atomic UInt
	// atomic go package
	channelLatestAcks [256]uint32

	// Conds to signal Channel Send thread
	// that Acks / Data are available
	// to send
	channelSendConds [256](*sync.Cond)
}

func (ca *chanApp) init(nrecv nrecvfn, nsend nsendfn, nclose nclosefn,
	maxFrSz int, sendBufSz int, windowSz int) {}
func (ca *chanApp) start() {}
func (ca *chanApp) shutdown() {}
