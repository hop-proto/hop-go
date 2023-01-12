// Package tubes implements the multiplexing of raw data into logical channels of a hop session
package tubes

import (
	"io"
	"net"
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

	// Unreliable tubes can be in three states:
	// created: Indicates the tube has been created and is waiting for the remote peer send back an initiate frame
	// initiated: Indicates the tube is ready to read and write data
	// closed: Indicates the tube is done reading and writing data
	state        atomic.Value
	initiated    chan struct{}
	initiateDone chan struct{}
	senderDone   chan struct{}
	closed       chan struct{}

	recv *common.DeadlineChan[[]byte]
	send *common.DeadlineChan[[]byte]

	frameNo atomic.Uint32

	localAddr  net.Addr
	remoteAddr net.Addr

	log *logrus.Entry
}

// Unreliable tubes implement net.Conn
var _ net.Conn = &Unreliable{}

// Unreliable tubes work as a drop in replacement for UDP
var _ transport.UDPLike = &Unreliable{}

// Unreliable tubes are message oriented data streams
var _ transport.MsgConn = &Unreliable{}

// Unreliable tubes are tubes
var _ Tube = &Unreliable{}

func (u *Unreliable) sender() {
	for b := range u.send.C {
		u.sendQueue <- b
	}

	u.log.Debug("sender ended")
	close(u.senderDone)
}

func (u *Unreliable) makeInitFrame(req bool) initiateFrame {
	return initiateFrame{
		tubeID:     u.id,
		tubeType:   u.tType,
		data:       []byte{},
		dataLength: 0,
		frameNo:    0,
		windowSize: 0,
		flags: frameFlags{
			ACK:  false,
			FIN:  false,
			REQ:  req,
			RESP: !req,
			REL:  false,
		},
	}
}

// req: whether the tube is requesting to initiate a tube (true), or whether is responding to an initiation request (false)
func (u *Unreliable) initiate(req bool) {
	defer close(u.initiateDone)

	// RESP init frames are generated in receiveInitiatePkt
	if req {
		notInit := true
		ticker := time.NewTicker(retransmitOffset)
		for notInit {
			p := u.makeInitFrame(req)
			u.sendQueue <- p.toBytes()

			select {
			case <-ticker.C:
				u.log.Info("init rto exceeded")
			case <-u.initiated:
			case <-u.closed:
				return
			}
			notInit = u.state.Load() == created
		}
	}

	go u.sender()
}

func (u *Unreliable) receiveInitiatePkt(pkt *initiateFrame) error {
	// Log the packet
	u.log.WithFields(logrus.Fields{
		"frameno": pkt.frameNo,
		"req":     pkt.flags.REQ,
		"resp":    pkt.flags.RESP,
		"rel":     pkt.flags.REL,
		"ack":     pkt.flags.ACK,
		"fin":     pkt.flags.FIN,
	}).Debug("receiving initiate packet")

	if u.state.CompareAndSwap(created, initiated) {
		close(u.initiated)
	}

	// Send a RESP packet in response to REQ packets
	if pkt.flags.REQ && u.state.Load() != closed {
		p := u.makeInitFrame(false)
		u.sendQueue <- p.toBytes()
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
	select {
	case <-u.initiated:
		break
	case <-u.closed:
		break
	}
	msg, err := u.recv.Recv()
	if err != nil {
		return
	}
	n = copy(b, msg)
	if n < len(msg) {
		err = transport.ErrBufOverflow
		// net.UDPConn discards buffer leftovers, so Unreliable Tubes does the same
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
	select {
	case <-u.initiated:
		break
	case <-u.closed:
		break
	}
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
		frameNo:    u.frameNo.Load(),
		data:       b,
	}
	u.frameNo.Add(1)

	err = u.send.Send(pkt.toBytes())
	if err != nil {
		return
	}
	n = len(b)
	u.log.WithFields(logrus.Fields{
		"frameNo":    pkt.frameNo,
		"dataLength": pkt.dataLength,
	}).Trace("wrote packet")
	return n, 0, err
}

// Close implements the net.Conn interface. Future io operations will return io.EOF
func (u *Unreliable) Close() error {
	oldState := u.state.Swap(closed)
	if oldState == closed {
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
		frameNo:    u.frameNo.Load(),
		data:       []byte{},
	}
	u.frameNo.Add(1)

	err := u.send.Send(pkt.toBytes())

	u.send.Close()
	u.recv.Close()

	close(u.send.C)

	if oldState == initiated {
		<-u.senderDone
	}

	close(u.closed)

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
	select {
	case <-u.initiated:
		break
	case <-u.closed:
		break
	}
	return u.recv.SetDeadline(t)
}

// SetWriteDeadline implements net.Conn
func (u *Unreliable) SetWriteDeadline(t time.Time) error {
	select {
	case <-u.initiated:
		break
	case <-u.closed:
		break
	}
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

// WaitForClose blocks until the tube is done closing
func (u *Unreliable) WaitForClose() {
	<-u.closed
	<-u.initiateDone
}

func (u *Unreliable) getLog() *logrus.Entry {
	return u.log
}
