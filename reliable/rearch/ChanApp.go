package main

import (
	"fmt"
	"net"
	"sync"
	"time"
	"errors"
)

// Network Send Buffer Size
// Channel Recv, Read, Write buf size
var BUF_SIZE = 64
// Window Size in Bytes
var WINDOW_SIZE = 4096
// Clock Cycle
var CLOCK_CYCLE = 50*time.Millisecond

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
	internal_ca.init(nrecv, nsend, nclose, maxFrSz)
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
	return &ChannelListener{listenerCh: ca.ca.listenerCh}
}

func (ca *ChannelApp) MakeChannel(cid int) (*Channel, error) {
	ch, err := ca.ca.makeCh(cid)
	return ch, err
}

// Implements net.Listener
type ChannelListener struct {
	// Go Channel used to close listener
	quit chan struct{}
	// Go Channel used to deliver Channels
	listenerCh chan *Channel
	// Operation Lock
	mu sync.Mutex
	// Closed Status
	closed bool
}

func (cl *ChannelListener) Accept() (*Channel, error) {
	select {
		case <-cl.quit:
			return nil, errors.New("Channel Listener is closed")
		case ch, ok := <-cl.listenerCh:
			if !ok {
				return ch, errors.New("Channel Application is closed")
			}
			return ch, nil
	}
}

func (cl *ChannelListener) Close() error {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.closed {
		return errors.New("Listener already closed")
	}
	// Terminates all threads blocked on
	// Accept() calls and future calls
	close(cl.quit)
	cl.closed = true
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
	// Goroutine Wait Group
	wg sync.WaitGroup
	// Network Recv Fn
	nrecv nrecvfn
	// Network Send Fn
	nsend nsendfn
	// Network Close Fn
	nclose nclosefn
	// Max Frame Size
	maxFrSz int
	// Go Channel used internally to deliver
	// Channels to Listeners
	listenerCh chan *Channel
	// Go Channel used internally to send frames
	nsendCh chan []byte
	// Go Channels used internally for routing frames
	// to channels.
	channelRecvChs [256](chan []byte)
	// Channel windows
	channelWindows [256]*Window
	// Channel Tickers used for clock ticks
	channelTickers [256](*time.Ticker)
	// Channel RTO timers used as atomic int
	channelTimers [256]int32
	// Go Channels used internally to route contiguous
	// data sections to channel.read() calls
	channelReadChs [256](chan []byte)
	// Go Channels used internally to route data
	// to be sent from channel.write() calls
	channelWriteChs [256](chan []byte)
	// Latest Ack used as an Atomic UInt
	// atomic go package
	channelLatestAcks [256]uint32
	// Conds to signal Channel Send thread
	// that Acks / Data are available
	// to send
	channelSendConds [256](*sync.Cond)
	// Cond variable to wait for channel
	// responses
	channelRespConds [256](*sync.Cond)
	// Mutex and Channel Active Status
	channelActiveMu [256]sync.Mutex
	channelActive [256]bool
}

func (ca *chanApp) init(nrecv nrecvfn, nsend nsendfn, nclose nclosefn,
	maxFrSz int) {
	ca.maxFrSz = maxFrSz
	ca.nrecv = nrecv
	ca.nsend = nsend
	ca.nclose = nclose
	ca.listenerCh = make(chan *Channel, 256)
	ca.nsendCh = make(chan []byte, BUF_SIZE)
	for i := 0; i < 256; i++ {
		ca.channelRecvChs[i] = make(chan []byte, BUF_SIZE)
		ca.channelReadChs[i] = make(chan []byte, BUF_SIZE)
		ca.channelWriteChs[i] = make(chan []byte, BUF_SIZE)
		ca.channelWindows[i] = &Window{}
		ca.channelWindows[i].init(WINDOW_SIZE)
		ca.channelSendConds[i] = &sync.Cond{L: &sync.Mutex{}}
		ca.channelRespConds[i] = &sync.Cond{L: &sync.Mutex{}}
	}
}

func (ca *chanApp) start() {
	for i := 0; i < 256; i++ {
		ca.channelTickers[i] = time.NewTicker(CLOCK_CYCLE)
	}
	ca.wg.Add(1)
	go ca.nsendThread()
}

func (ca *chanApp) shutdown() {
	// Terminates Listeners
	close(ca.listenerCh)
	// Terminates the nsendThread
	close(ca.nsendCh)
	for i := 0; i < 256; i++ {
		close(ca.channelRecvChs[i])
		close(ca.channelReadChs[i])
		close(ca.channelWriteChs[i])
		ca.channelSendConds[i].Signal()
		ca.channelRespConds[i].Signal()
		ca.channelTickers[i].Stop()
		// Is this necessary if we use tickers?
		updateTimer(&ca.channelTimers[i], -100)
	}
	// Close Network
	ca.nclose()
	ca.wg.Wait()
	for i := 0; i < 256; i++ {
		// Garbage Collection
		ca.channelWindows[i] = nil
		ca.channelTickers[i] = nil
		ca.channelSendConds[i] = nil
		ca.channelRespConds[i] = nil
	}
}

func (ca *chanApp) nsendThread() {
	defer ca.wg.Done()
	for frame := range ca.nsendCh {
		fmt.Println("Network Sending", frame)
		ca.nsend(frame)
	}
	fmt.Println("Network Sending Thread Exiting")
}

func (ca *chanApp) makeCh(cid int) (*Channel, error) {
	ca.channelActiveMu[cid].Lock()
	defer ca.channelActiveMu[cid].Unlock()
	if ca.channelActive[cid] {
		return nil, errors.New("Channel already is active")
	}
	// TODO send req and block on resp cond
	// set channel active to true
	return nil, nil
}
