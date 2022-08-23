// Package tubes implements the multiplexing of raw data into logical channels of a hop session
package tubes

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
)

// How David would approach this:
//   1. Implement the message framing (seq no, ack no, all that stuff)
//   2. Implement Read and Write assuming no buffering or out of order or anything like that, using the framing
//   3. Buffering
//   4. Concurrency controls (locks)

const retransmitOffset = time.Millisecond * 500

const windowSize = 128

// TubeType represents identifier bytes of Tubes.
type TubeType byte

const (
	created    int32 = iota
	initiated  int32 = iota
	closeStart int32 = iota
	closed     int32 = iota
)

var errTubeNotInitiated = errors.New("tube not initiated")

// Reliable implements a reliable and receiveWindow tube on top
type Reliable struct {
	reset       chan struct{}
	closing     chan struct{}
	tType       TubeType
	id          byte
	localAddr   net.Addr
	recvWindow  receiver
	remoteAddr  net.Addr
	sender      sender
	sendQueue   chan []byte
	tubeState atomic.Int32 // TODO(hosono) this could just be atomic
	initRecv  chan struct{}
	sendStopped chan struct{}
	l         sync.Mutex
	finAcked  atomic.Bool
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

// Reliable tubes are tubes
var _ Tube = &Reliable{}

func (r *Reliable) getState() state {
	r.m.Lock()
	defer r.m.Unlock()
	return r.tubeState
}

func (r *Reliable) send() {
	for r.getState() == initiated || r.getState() == closeStart {
		pkt := <-r.sender.sendQueue
		pkt.tubeID = r.id
		pkt.ackNo = r.recvWindow.getAck()
		pkt.flags.ACK = true
		pkt.flags.REL = true
		logrus.Debug("sending pkt ", pkt.frameNo, pkt.ackNo, pkt.flags.FIN, pkt.flags.ACK)
		r.sendQueue <- pkt.toBytes()
	}
}

func newReliableTubeWithTubeID(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tubeType TubeType, tubeID byte) *Reliable {
	r := makeReliableTube(underlying, netConn, sendQueue, tubeType, tubeID)
	go r.initiate(false)
	return r
}

func makeReliableTube(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tType TubeType, tubeID byte) *Reliable {
	r := &Reliable{
		id:          tubeID,
		localAddr:   laddr,
		remoteAddr:  raddr,
		sendStopped: make(chan struct{}, 1),
		initRecv:    make(chan struct{}),
		closing:     make(chan struct{}, 1),
		reset:       make(chan struct{}, 1),
		recvWindow: receiver{
			dataReady:   common.NewDeadlineChan[struct{}](1),
			buffer:      new(bytes.Buffer),
			fragments:   make(PriorityQueue, 0),
			windowSize:  windowSize,
			windowStart: 1,
		},
		sender: sender{
			ackNo:  1,
			buffer: make([]byte, 0),
			// closed defaults to false
			// finSent defaults to false
			frameDataLengths: make(map[uint32]uint16),
			RTOTicker:        time.NewTicker(retransmitOffset),
			RTO:              retransmitOffset,
			windowSize:       windowSize,
			endRetransmit:    make(chan struct{}),
			windowOpen:       make(chan struct{}, 1),
			sendQueue:        make(chan *frame),
			retransmitEnded:  make(chan struct{}, 1),
		},
		sendQueue: sendQueue,
		tType:     tType,
	}
	r.sender.frameNo.Store(1)
	r.tubeState.Store(created)
	r.recvWindow.init()
	return r
}

func newReliableTube(muxer *Muxer, tType TubeType) (*Reliable, error) {
	cid := []byte{0}
	n, err := rand.Read(cid) // TODO(hosono) make sure there are no tube conflicts
	if err != nil || n != 1 {
		return nil, err
	}
	r := makeReliableTube(underlying, netConn, sendQueue, tType, cid[0])
	go r.initiate(true)
	return r, nil
}

/* req: whether the tube is requesting to initiate a tube (true), or whether is respondding to an initiation request (false).*/
func (r *Reliable) initiate(req bool) {
	//logrus.Errorf("Tube %d initiated", r.id)
	tubeType := r.tType
	notInit := true

	for notInit {
		p := initiateFrame{
			tubeID:     r.id,
			tubeType:   tubeType,
			data:       []byte{},
			dataLength: 0,
			frameNo:    0,
			windowSize: r.recvWindow.windowSize,
			flags: frameFlags{
				ACK:  true,
				FIN:  false,
				REQ:  req,
				RESP: !req,
				REL:  true,
			},
		}
		r.sendQueue <- p.toBytes()
		r.m.Lock()
		notInit = r.tubeState == created
		r.m.Unlock()
		timer := time.NewTimer(retransmitOffset)
		<-timer.C
	}
	ticker := time.NewTicker(retransmitOffset)
	for notInit {
		r.sendQueue <- p.toBytes()
		select {
		case <-ticker.C:
			continue
		case <-r.initRecv:
			notInit = r.tubeState.Load() == created
		}
	}
	go r.send()
	r.sender.Start()
}

func (r *Reliable) send() {
	for pkt := range(r.sender.sendQueue) {
		pkt.tubeID = r.id
		pkt.ackNo = r.recvWindow.getAck()
		pkt.flags.ACK = true
		pkt.flags.REL = true
		r.sendQueue <- pkt.toBytes()
	}
	r.sendStopped <- struct{}{}
}

func (r *Reliable) receive(pkt *frame) error {
	r.m.Lock()
	defer r.m.Unlock()
	if r.tubeState != initiated {
		//logrus.Error("receiving non-initiate tube frames when not initiated")
		return errors.New("receiving non-initiate tube frames when not initiated")
	}

	logrus.Tracef("receving packet. ackno: %d, ack? %t, fin? %t", pkt.ackNo, pkt.flags.ACK, pkt.flags.FIN)
	err := r.recvWindow.receive(pkt)
	if pkt.flags.ACK {
		r.sender.recvAck(pkt.ackNo)
	}

	if pkt.flags.FIN && !r.finAcked.CompareAndSwap(false, true) {
		r.sender.sendEmptyPacket()
	}
	// TODO(hosono) fix this check to be better
	/*
	 *if (r.recvWindow.getAck() - r.sender.lastAckSent.Load()) >= windowSize / 2{
	 *    r.sender.sendEmptyPacket()
	 *}
	 */

	select {
	case r.closing <- struct{}{}:
		break
	default:
		break
	}

	return err
}

func (r *Reliable) receiveInitiatePkt(pkt *initiateFrame) error {
	if r.tubeState.Load() == created {
		r.recvWindow.m.Lock()
		r.recvWindow.ackNo = 1
		r.recvWindow.m.Unlock()
		//logrus.Debug("INITIATED! ", pkt.flags.REQ, " ", pkt.flags.RESP)
		r.tubeState.Store(initiated)
		r.sender.recvAck(1)
		close(r.initRecv)
	}

	return nil
}

func (r *Reliable) WaitForInitiated() {
	<-r.initRecv
}

func (r *Reliable) Read(b []byte) (n int, err error) {
	if r.tubeState.Load() != initiated {
		err = errTubeNotInitiated
		return
	}
	return r.recvWindow.read(b)
}

func (r *Reliable) Write(b []byte) (n int, err error) {
	if r.tubeState.Load() != initiated {
		err = errTubeNotInitiated
		return
	}
	return r.sender.write(b)
}

// WriteMsgUDP implements the "UDPLike" interface for transport layer NPC. Trying to make tubes have the same funcs as net.UDPConn
func (r *Reliable) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if r.tubeState.Load() != initiated {
		err = errTubeNotInitiated
		return
	}
	length := len(b)
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(length))
	_, e := r.Write(append(h, b...))
	return length, 0, e
}

// ReadMsgUDP implements the "UDPLike" interface for transport layer NPC. Trying to make tubes have the same funcs as net.UDPConn
func (r *Reliable) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	if r.tubeState.Load() != initiated {
		err = errTubeNotInitiated
		return
	}
	h := make([]byte, 2)
	_, e := io.ReadFull(r, h)
	if e != nil {
		return 0, 0, 0, nil, e
	}
	length := binary.BigEndian.Uint16(h)
	data := make([]byte, length)
	_, e = io.ReadFull(r, data)
	n = copy(b, data)
	return n, 0, 0, nil, e
}

func (r *Reliable) Reset() (err error) {
	// TODO(hosono) add a reset flag

	oldState := r.tubeState.Swap(closed)
	if oldState == closed {
		logrus.Warnf("Resetting of closed tube %d", r.id)
		return io.EOF
	}

	logrus.Warnf("Resetting tube %d", r.id)

	r.sender.Reset()
	r.recvWindow.Close()
	close(r.sender.sendQueue)
	<-r.sendStopped

	select {
	case r.reset <- struct{}{}:
		break
	default:
		break
	}

	return
}

// Close handles closing reliable tubes
func (r *Reliable) Close() (err error) {
	if !r.tubeState.CompareAndSwap(initiated, closeStart) {
		return io.EOF
	}
	logrus.Debugf("Starting close of tube %d", r.id)

	// Prevent future writes from succeeding
	r.sender.Close()
	r.recvWindow.Close()

	// Wait until the other end of the connection has received the FIN packet from the other side.
closeLoop:
	for {
		select {
		case <-r.closing:
			if r.sender.unsentFramesRemaining() == 0 && r.recvWindow.closed.Load() {
				logrus.Debugf("sent all frames and got fin for tube %d", r.id)
				break closeLoop
			} else {
				logrus.Debugf("closing. packets left to ack: %d", r.sender.unsentFramesRemaining())
			}
		case <-r.reset:
			logrus.Debugf("got reset in close loop for tube %d", r.id)
			break closeLoop
		}
	}
	// TODO(hosono) correctly linger
	time.Sleep(5 * time.Second)

	r.l.Lock()
	defer r.l.Unlock()
	r.sender.Reset()
	logrus.Debugf("closed tube: %v", r.id)

	close(r.sender.sendQueue)
	<-r.sendStopped
	r.tubeState.Store(closed)

	return nil
}

// Type returns tube type
func (r *Reliable) Type() TubeType {
	return r.tType
}

// GetID returns the tube ID
func (r *Reliable) GetID() byte {
	return r.id
}

// IsReliable returns whether the tube is reliable. Always true
func (r *Reliable) IsReliable() bool {
	return true
}

// LocalAddr returns tube local address
func (r *Reliable) LocalAddr() net.Addr {
	return r.localAddr
}

// RemoteAddr returns the remote address for the tube
func (r *Reliable) RemoteAddr() net.Addr {
	return r.remoteAddr
}

// SetDeadline (not implemented)
func (r *Reliable) SetDeadline(t time.Time) error {
	r.SetReadDeadline(t)
	r.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline (not implemented)
func (r *Reliable) SetReadDeadline(t time.Time) error {
	return r.recvWindow.dataReady.SetDeadline(t)
}

// SetWriteDeadline (not implemented)
func (r *Reliable) SetWriteDeadline(t time.Time) error {
	r.sender.l.Lock()
	defer r.sender.l.Unlock()
	r.sender.deadline = t
	return nil
}
