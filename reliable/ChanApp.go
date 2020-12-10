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
// Retransmission Time RTO
var RTO = 250*time.Millisecond

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
		default:
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
	// Network Goroutine Wait Group
	nwg sync.WaitGroup
	// Channel Goroutine Wait Group
	chwg sync.WaitGroup
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
	// Go Channels used internally to route contiguous
	// data sections to channel.read() calls
	channelReadChs [256](chan []byte)
	// Go Channels used internally to route data
	// to be sent from channel.write() calls
	channelWriteChs [256](chan []byte)
	// Latest Ctr seen used as an Atomic UInt
	// atomic go package
	channelLatestCtrSeen [256]uint32
	// Latest Ctr seen used as an Atomic UInt
	// atomic go package
	channelLatestAckSeen [256]uint32
	// Signals channelSendThread to send ack
	channelSendAckChs [256](chan struct{})
	// Signals MakeCh() calls that channel
	// is available
	channelMakeChSignal [256](chan struct{})
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
		ca.channelSendAckChs[i] = make(chan struct{}, 1)
		ca.channelMakeChSignal[i] = make(chan struct{}, 1)
		ca.channelWindows[i] = &Window{}
		ca.channelWindows[i].init(WINDOW_SIZE)
	}
}

func (ca *chanApp) start() {
	ca.nwg.Add(1)
	go ca.nRecvThread()
	ca.nwg.Add(1)
	go ca.nSendThread()
	for i := 0; i < 256; i++ {
		ca.channelTickers[i] = time.NewTicker(RTO)
		ca.chwg.Add(1)
		go ca.channelRecvThread(i)
		ca.chwg.Add(1)
		go ca.channelSendThread(i)
	}
}

func (ca *chanApp) shutdown() {
	for i := 0; i < 256; i++ {
		close(ca.channelRecvChs[i])
		close(ca.channelReadChs[i])
		close(ca.channelWriteChs[i])
		close(ca.channelSendAckChs[i])
		close(ca.channelMakeChSignal[i])
		ca.channelTickers[i].Stop()
	}
	ca.chwg.Wait()
	// Terminates Listeners
	close(ca.listenerCh)
	// Terminates the nSendThread
	close(ca.nsendCh)
	// Close Network which terminates nRecvThread
	ca.nclose()
	ca.nwg.Wait()
	for i := 0; i < 256; i++ {
		// Garbage Collection
		ca.channelWindows[i] = nil
		ca.channelTickers[i] = nil
	}
}

func (ca *chanApp) send(frame []byte) {
	select {
		case ca.nsendCh <- frame:
		default:
	}
}

func (ca *chanApp) nRecvThread(){
	defer ca.nwg.Done()
	for {
		n, buf, err := ca.nrecv()
		if err != nil {
			// Network Conn is closed
			// Happens when Channel Appplication is shutdown
			fmt.Println("Network Receiving Thread Exiting")
			return
		}
		frame := buf[:n]
		// Routing frame to channels is best effort
		select {
			case ca.channelRecvChs[getCID(frame)] <- frame:
			default:
		}
	}
}

func (ca *chanApp) nSendThread() {
	defer ca.nwg.Done()
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
	// TODO send req and block on read from makeCh go channel?
	// <-channelMakeChSignal[cid]
	// ca.channelActive[cid] = true
	return nil, nil
}

func (ca *chanApp) channelRecvThread(cid int) {
	defer ca.chwg.Done()
	var latestCtrSeen uint32 = 0
	for frame := range ca.channelRecvChs[cid] {
		if isReq(frame) {
			fmt.Println("Channel", cid, "received request frame")
			// need to send channel to listenerCh
			// since auto accept
			// need to send response
		} else if isRep(frame) {
			fmt.Println("Channel", cid, "received response frame")
			// handle processing logic
			/* 
			select {
				case ca.channelMakeChSignal[cid] <- struct{}{}:
				default:
			}
			*/
		} else if isFin(frame) {
			// handle Fin Logic
		} else { // Data frame
			oldAckSeen := readCtr(&ca.channelLatestAckSeen[cid])
			fmt.Println("Channel", cid, "has seen Ack", oldAckSeen)
			fmt.Println("Channel", cid, "is seeing Ack", getAck(frame))
			if oldAckSeen < getAck(frame) {
				// Reset RTO
				ca.channelTickers[cid].Reset(RTO)
				updateCtr(&ca.channelLatestAckSeen[cid], getAck(frame))
			}
			// Frame has data / not just an Ack Frame
			if getDataSz(frame) > 0 {
				frameCtr := getCtr(frame)
				// Frame not seen before
				if !(frameCtr <= latestCtrSeen || ca.channelWindows[cid].hasCtr(frameCtr)) {
					pushed := ca.channelWindows[cid].push(frame)
					if !pushed {
						// Window is full
						continue
					}
					// For loop puts all contiguous data frames into read ch buffer
					for ca.channelWindows[cid].hasNextFrame(latestCtrSeen) &&
						len(ca.channelReadChs[cid]) < BUF_SIZE {
						// Window contains frame after the latest frame acknowledged
						// ReadCh for that CID still has space
						poppedFrame := ca.channelWindows[cid].pop()
						latestCtrSeen++
						fmt.Println("Channel", cid, "receiving data", getData(poppedFrame))
						ca.channelReadChs[cid] <- getData(poppedFrame)
					}
					updateCtr(&ca.channelLatestCtrSeen[cid], latestCtrSeen)
					fmt.Println("Channel", cid, "Latest Contigious Ctr Seen", latestCtrSeen)
				}
				// Signal Send Thread to send frame with latestCtrSeen
				// basically send an ACK frame
				// Done in nonblocking manner
				select {
					case ca.channelSendAckChs[cid] <-struct{}{}:
					default:
				}
			}
		}
	}
}

func (ca *chanApp) channelSendThread(cid int) {
	defer ca.chwg.Done()
	var ctr uint32 = 1
	for {
		select {
		case data, ok := <-ca.channelWriteChs[cid]:
				if !ok {
					// Write Ch has closed
					return
				}
				latestCtrSeen := readCtr(&ca.channelLatestCtrSeen[cid])
				frame := buildFrame(cid, 0, latestCtrSeen, ctr, data)
				ctr++
				fmt.Println("Sending Frame", frame)
				ca.send(frame)
				//add to RTQueue
		//	case <-ca.channelTickers[cid]:
		//		update the RTQueue based on latestAckSeen
		//		send stuff in the RTQueue with latest ctr
		//		// increment ctr
		case _, ok := <-ca.channelSendAckChs[cid]:
				if !ok {
					// SendAckCh closed
					return
				}
				latestCtrSeen := readCtr(&ca.channelLatestCtrSeen[cid])
				// Empty frame with ignored ctr
				frame := buildFrame(cid, 0, latestCtrSeen, 0, []byte{})
				ca.send(frame)
		}
	}
}
