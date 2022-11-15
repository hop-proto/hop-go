// Package tubes implements the multiplexing of raw data into logical channels of a hop session
package tubes

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
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

type state int32

const (
	created    state = iota
	initiated  state = iota

	// These states are pull from the TCP state machine.
	closeWait  state = iota
	lastAck    state = iota
	finWait1   state = iota
	finWait2   state = iota
	closing    state = iota
	timeWait   state = iota
	closed     state = iota

)

var errBadTubeState = errors.New("tube in bad state")

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
	// TODO(hosono) probably we shouldn't just have one lock that manages everything
	// +checklocks:l
	tubeState   state
	initRecv    chan struct{}
	sendStopped chan struct{}
	l           sync.Mutex
	finAcked    atomic.Bool
	log         *logrus.Entry
}

// Reliable implements net.Conn
var _ net.Conn = &Reliable{}

// Reliable tubes are tubes
var _ Tube = &Reliable{}

/* req: whether the tube is requesting to initiate a tube (true), or whether is respondding to an initiation request (false).*/
func (r *Reliable) initiate(req bool) {
	//r.log.Errorf("Tube %d initiated", r.id)
	tubeType := r.tType
	notInit := true

	p := initiateFrame{
		tubeID:     r.id,
		tubeType:   tubeType,
		data:       []byte{},
		dataLength: 0,
		frameNo:    0,
		windowSize: r.recvWindow.windowSize,
		flags: frameFlags{
			REQ:  req,
			RESP: !req,
			REL:  true,
			ACK:  true,
			FIN:  false,
		},
	}
	ticker := time.NewTicker(retransmitOffset)
	for notInit {
		r.sendQueue <- p.toBytes()
		select {
		case <-ticker.C:
			continue
		case <-r.initRecv:
			notInit = r.tubeState == created
		}
	}
	go r.send()
	r.sender.Start()
}

func (r *Reliable) send() {
	for pkt := range r.sender.sendQueue {
		pkt.tubeID = r.id
		pkt.ackNo = r.recvWindow.getAck()
		pkt.flags.ACK = true
		pkt.flags.REL = true
		r.sendQueue <- pkt.toBytes()
	}
	r.sendStopped <- struct{}{}
}

func (r *Reliable) receive(pkt *frame) error {
	r.l.Lock()
	defer r.l.Unlock()

	if r.tubeState == created || r.tubeState == closed {
		r.log.WithFields(logrus.Fields{
			"fin": pkt.flags.FIN,
			"state": r.tubeState,
		}).Errorf("receive for tube in bad state")
		r.Reset()
		return errBadTubeState
	}

	r.log.WithFields(logrus.Fields{
		"ackno": pkt.ackNo,
		"ack":   pkt.flags.ACK,
		"fin":   pkt.flags.FIN,
	}).Trace("receiving packet")
	err := r.recvWindow.receive(pkt)
	if pkt.flags.ACK {
		r.sender.recvAck(pkt.ackNo)
	}

	// handle closing states of FIN packets
	if pkt.flags.FIN {
		switch r.tubeState {
		case initiated:
			r.tubeState = closeWait
		case finWait1:
			r.tubeState = closing
		case finWait2:
			r.tubeState = timeWait
		}
		r.sender.sendEmptyPacket()
	}

	// State transitions for ACK of FIN
	if pkt.flags.ACK && r.tubeState != initiated && r.sender.unAckedFramesRemaining() == 0{
		switch r.tubeState {
		case finWait1:
			r.tubeState = finWait2
		case closing:
			r.tubeState = timeWait
		case lastAck:
			r.tubeState = closed
		}
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
	if r.tubeState == created {
		r.recvWindow.m.Lock()
		r.recvWindow.ackNo = 1
		r.recvWindow.m.Unlock()
		r.log.Debug("INITIATED!")
		r.tubeState = initiated
		r.sender.recvAck(1)
		close(r.initRecv)
	}

	return nil
}

func (r *Reliable) Read(b []byte) (n int, err error) {
	if r.tubeState == created {
		return 0, errBadTubeState
	}
	return r.recvWindow.read(b)
}

func (r *Reliable) Write(b []byte) (n int, err error) {
	if r.tubeState == created {
		return 0, errBadTubeState
	}
	return r.sender.write(b)
}

// WriteMsgUDP implements the "UDPLike" interface for transport layer NPC. Trying to make tubes have the same funcs as net.UDPConn
func (r *Reliable) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if r.tubeState == created {
		err = errBadTubeState
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
	if r.tubeState == created {
		err = errBadTubeState
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

// Reset immediately tears down the connection
func (r *Reliable) Reset() (err error) {
	// TODO(hosono) add a reset flag

	oldState := r.tubeState
	r.tubeState = closed
	if oldState == closed {
		r.log.Warn("Resetting closed tube")
		return io.EOF
	}

	r.log.Warn("Resetting tube")

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
	r.l.Lock()
	defer r.l.Unlock()

	switch r.tubeState {
	case created:
		return errors.New("tube not initiated")
	case initiated:
		r.tubeState = finWait1
	case closeWait:
		r.tubeState = lastAck
	default:
		return io.EOF
	}

	return r.sender.sendFin()


/*
 *    if !r.tubeState.CompareAndSwap(initiated, closeStart) {
 *        return io.EOF
 *    }
 *    r.log.Debug("Starting close")
 *
 *    // Prevent future writes from succeeding
 *    r.sender.Close()
 *    r.recvWindow.Close()
 *
 *    // Wait until the other end of the connection has received the FIN packet from the other side.
 *closeLoop:
 *    for {
 *        select {
 *        case <-r.closing:
 *            if r.sender.unsentFramesRemaining() == 0 && r.recvWindow.closed.Load() {
 *                r.log.Debug("sent all frames and got fin")
 *                break closeLoop
 *            } else {
 *                r.log.WithField("packet left to ack", r.sender.unsentFramesRemaining()).Debug("closing")
 *            }
 *        case <-r.reset:
 *            r.log.Debug("got reset in close loop")
 *            break closeLoop
 *        }
 *    }
 *    // TODO(hosono) correctly linger
 *    time.Sleep(5 * time.Second)
 *
 *    r.l.Lock()
 *    defer r.l.Unlock()
 *    r.sender.Reset()
 *    r.log.Debugf("closed tube")
 *
 *    close(r.sender.sendQueue)
 *    <-r.sendStopped
 *    r.tubeState.Store(closed)
 */

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

// LocalAddr returns the local address for the tube
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
