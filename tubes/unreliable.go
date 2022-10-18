// Package tubes implements the multiplexing of raw data into logical channels of a hop session
package tubes

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"hop.computer/hop/common"
	"hop.computer/hop/transport"

	"github.com/sirupsen/logrus"
)

// Unreliable implements UDP-like messages for Hop
type Unreliable struct {
	tType     TubeType
	id        byte
	sendQueue chan []byte
	m         sync.Mutex

	state     atomic.Value
	initiated chan struct{}

	// true if this tube began the request. false otherwise
	// TODO(hosono) can be replaced with parity of tubeID
	req bool

	recv *common.DeadlineChan[[]byte]
	send *common.DeadlineChan[[]byte]

	// +checklocks:m
	frameNo uint32

	localAddr  net.Addr
	remoteAddr net.Addr

	log *logrus.Entry
}

// TODO(hosono) pick a value for this
var maxBufferedPackets = 1000

// Unreliable tubes implement net.Conn
var _ net.Conn = &Unreliable{}

// Unreliable tubes work as a drop in replacement for UDP
var _ transport.UDPLike = &Unreliable{}

// Unreliable tubes are message oriented data streams
var _ transport.MsgConn = &Unreliable{}

// Unreliable tubes are tubes
var _ Tube = &Unreliable{}

/*
func newUnreliableTube(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tubeType TubeType, log *logrus.Entry) (*Unreliable, error) {
	cid := []byte{0}
	n, err := rand.Read(cid)
	if err != nil || n != 1 {
		return nil, err
	}
	u := makeUnreliableTube(underlying, netConn, sendQueue, tubeType, cid[0], log)
	go u.initiate(true)
	return u, nil
}

func newUnreliableTubeWithTubeID(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tubeType TubeType, tubeID byte, log *logrus.Entry) *Unreliable {
	u := makeUnreliableTube(underlying, netConn, sendQueue, tubeType, tubeID, log)
	go u.initiate(false)
	return u
}

func makeUnreliableTube(underlying transport.MsgConn, netConn net.Conn, sendQueue chan []byte, tType TubeType, tubeID byte, log *logrus.Entry) *Unreliable {
	u := &Unreliable{
		tType:      tType,
		id:         tubeID,
		sendQueue:  sendQueue,
		localAddr:  netConn.LocalAddr(),
		remoteAddr: netConn.RemoteAddr(),
		recv:       common.NewDeadlineChan[[]byte](maxBufferedPackets),
		send:       common.NewDeadlineChan[[]byte](maxBufferedPackets),
		state:      atomic.Value{},
		initiated:   make(chan struct{}),
	}
	return u
}
*/

func (u *Unreliable) sender() {
	for {
		// TODO(hosono) this will busywait if the deadline expires
		b, err := u.send.Recv()
		if err != nil {
			if err == os.ErrDeadlineExceeded {
				continue
			} else if err == io.EOF {
				break
			}
		}
		u.sendQueue <- b
	}
	// TODO(hosono) this won't finish because this channel is not closed
	for pkt := range u.send.C {
		u.sendQueue <- pkt
	}
}

// req: whether the tube is requesting to initiate a tube (true), or whether is responding to an initiation request (false)
func (u *Unreliable) initiate(req bool) {
	if req {
		u.state.Store(created)
	} else {
		u.state.Store(initiated)
	}

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

		if req {
			timer := time.NewTimer(retransmitOffset)
			select {
			case <-timer.C:
				u.log.Warn("init rto exceeded")
				break
			case <-u.initiated:
				break
			}
		}
		notInit = u.state.Load() == created
	}

	go u.sender()
}

func (u *Unreliable) receiveInitiatePkt(pkt *initiateFrame) error {
	u.log.Debugf("receive initiate frame")

	u.state.CompareAndSwap(created, initiated)

	if !u.req {
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
				REQ:  false,
				RESP: true,
				REL:  false,
			},
		}
		u.sendQueue <- p.toBytes()
	}

	select {
	case u.initiated <- struct{}{}:
		break
	default:
		break
	}

	return nil
}

func (u *Unreliable) receive(pkt *frame) error {
	u.recv.C <- pkt.data
	if pkt.flags.FIN {
		u.recv.Close()
	}
	return nil
}

// Read implements net.Conn. It wraps ReadMsgUDP
func (u *Unreliable) Read(b []byte) (n int, err error) {
	n, _, _, _, err = u.ReadMsgUDP(b, nil)
	return
}

// ReadMsg implements transport.MsgConn. It wraps Read
func (u *Unreliable) ReadMsg(b []byte) (n int, err error) {
	n, err = u.Read(b)
	return
}

// ReadMsgUDP implements the UDPLike interface. addr is always nil
func (u *Unreliable) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	msg, err := u.recv.Recv()
	if err != nil {
		return
	}
	n = copy(b, msg)
	if n < len(msg) {
		err = transport.ErrBufOverflow
		// TODO(hosono) save buffer leftovers?
	}
	return
}

// Write implements net.Conn. It wraps WriteMsgUDP
func (u *Unreliable) Write(b []byte) (n int, err error) {
	n, _, err = u.WriteMsgUDP(b, nil, nil)
	return
}

// WriteMsg implements transport.MsgConn. It wraps Write
func (u *Unreliable) WriteMsg(b []byte) (err error) {
	_, err = u.Write(b)
	return
}

// WriteMsgUDP implements implements the UDPLike interface
// oob and addr are ignored
func (u *Unreliable) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	u.m.Lock()
	defer u.m.Unlock()

	dataLength := uint16(len(b))
	if uint16(len(b)) > maxFrameDataLength {
		err = transport.ErrBufOverflow
		return
	}

	pkt := frame{
		tubeID: u.id,
		flags: frameFlags{
			ACK:  false,
			FIN:  false,
			REQ:  false,
			RESP: false,
			REL:  false,
		},

		dataLength: dataLength,
		frameNo:    u.frameNo,
		data:       b,
	}
	u.frameNo++

	err = u.send.Send(pkt.toBytes())
	if err != nil {
		return
	}
	n = len(b)
	return n, 0, err
}

// Close implements the net.Conn interface. Future io operations will return io.EOF
func (u *Unreliable) Close() error {
	u.m.Lock()
	defer u.m.Unlock()

	if u.state.Swap(closed) == closed {
		return io.EOF
	}

	pkt := frame{
		tubeID: u.id,
		flags: frameFlags{
			ACK:  false,
			FIN:  true,
			REQ:  false,
			RESP: false,
			REL:  false,
		},

		dataLength: 0,
		frameNo:    u.frameNo,
		data:       []byte{},
	}
	u.frameNo++

	err := u.send.Send(pkt.toBytes())

	u.frameNo++
	u.send.Close()
	u.recv.Close()

	return err
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
