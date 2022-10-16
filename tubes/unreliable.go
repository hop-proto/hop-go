// Package tubes implements the multiplexing of raw data into logical channels of a hop session
package tubes

import (
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	"hop.computer/hop/common"
	"hop.computer/hop/transport"
)

// Unreliable implements UDP-like messages for Hop
type Unreliable struct {
	tType     TubeType
	id        byte
	sendQueue chan []byte
	m         sync.Mutex
	// +checklocks:m
	tubeState state

	recv *common.DeadlineChan[[]byte]
	send *common.DeadlineChan[[]byte]

	localAddr  net.Addr
	remoteAddr net.Addr
}

var maxBufferedPackets = 1000

// Unreliable tubes implement net.Conn
var _ net.Conn = &Unreliable{}

// Unreliable tubes work as a drop in replacement for UDP
var _ transport.UDPLike = &Unreliable{}

// Unreliable tubes are tubes
var _ Tube = &Unreliable{}

func newUnreliableTube(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tubeType TubeType) (*Unreliable, error) {
	cid := []byte{0}
	n, err := rand.Read(cid)
	if err != nil || n != 1 {
		return nil, err
	}
	u := makeUnreliableTube(underlying, netConn, sendQueue, tubeType, cid[0])
	go u.initiate(true)
	return u, nil
}

func newUnreliableTubeWithTubeID(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tubeType TubeType, tubeID byte) (*Unreliable, error) {
	u := makeUnreliableTube(underlying, netConn, sendQueue, tubeType, tubeID)
	go u.initiate(false)
	return u, nil
}

func makeUnreliableTube(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tType TubeType, tubeID byte) *Unreliable {
	u := &Unreliable{
		tType:      tType,
		id:         tubeID,
		sendQueue:  sendQueue,
		localAddr:  netConn.LocalAddr(),
		remoteAddr: netConn.RemoteAddr(),
		recv:       common.NewDeadlineChan[[]byte](maxBufferedPackets),
		send:       common.NewDeadlineChan[[]byte](maxBufferedPackets),
	}
	return u
}

// req: whether the tube is requesting to initiate a tube (true), or whether is respondding to an initiation request (false)
func (u *Unreliable) initiate(req bool) {
	notInit := true

	for notInit {
		p := initiateFrame{
			tubeID:     u.id,
			tubeType:   u.tType,
			data:       []byte{},
			dataLength: 0,
			frameNo:    0,
			windowSize: 0,
			flags: frameFlags{
				ACK:  true,
				FIN:  false,
				REQ:  req,
				RESP: !req,
				REL:  false,
			},
		}
		u.sendQueue <- p.toBytes()
		u.m.Lock()
		notInit = u.tubeState == created
		u.m.Unlock()
		timer := time.NewTimer(retransmitOffset)
		<-timer.C
	}
}

func (u *Unreliable) receiveInitiatePkt(pkt *initiateFrame) error {
	u.m.Lock()
	defer u.m.Unlock()

	if u.tubeState == created {
		u.tubeState = initiated
	}

	return nil
}

func (u *Unreliable) receive(pkt *frame) error {
	u.recv.C <- pkt.data
	return nil
}

// Read implements net.Conn. It wraps ReadMsgUDP
func (u *Unreliable) Read(b []byte) (n int, err error) {
	n, _, _, _, err = u.ReadMsgUDP(b, nil)
	return
}

// ReadMsgUDP implements the UDPLike interface
func (u *Unreliable) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	msg, err := u.recv.Recv()
	if err != nil {
		return
	}
	n = copy(b, msg)
	if n < len(msg) {
		err = transport.ErrBufUnderflow
		// TODO(hosono) save buffer leftovers?
	}
	return
}

// Write implements net.Conn. It wraps WriteMsgUDP
func (u *Unreliable) Write(b []byte) (n int, err error) {
	n, _, err = u.WriteMsgUDP(b, nil, u.remoteAddr.(*net.UDPAddr))
	return
}

// WriteMsgUDP implements implements the UDPLike interface
// oob and addr are ignored
func (u *Unreliable) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	err = u.send.Send(b)
	if err != nil {
		return
	}
	n = len(b)
	return
}

// Close implements the net.Conn interface. Future io operations will return io.EOF
func (u *Unreliable) Close() error {
	u.m.Lock()
	defer u.m.Unlock()
	if u.tubeState == closed {
		return io.EOF
	}
	u.send.Close()
	u.recv.Close()

	return nil
}

// LocalAddr implements net.Conn
func (u *Unreliable) LocalAddr() net.Addr {
	return u.localAddr
}

// RemoteAddr implements net.Conn
func (u *Unreliable) RemoteAddr() net.Addr {
	return u.remoteAddr
}

// SetDeadline implements net.Conn
func (u *Unreliable) SetDeadline(t time.Time) error {
	u.SetReadDeadline(t)
	u.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline implements net.Conn
func (u *Unreliable) SetReadDeadline(t time.Time) error {
	return u.recv.SetDeadline(t)
}

// SetWriteDeadline implements net.Conn
func (u *Unreliable) SetWriteDeadline(t time.Time) error {
	return u.send.SetDeadline(t)
}

// Type returns the tube type
func (u *Unreliable) Type() TubeType {
	return u.tType
}

// GetID returns the ID number of the tube
func (u *Unreliable) GetID() byte {
	return u.id
}

// IsReliable returns whether the tube is reliable. Always false
func (u *Unreliable) IsReliable() bool {
	return false
}
