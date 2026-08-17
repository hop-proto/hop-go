package tubes

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"hop.computer/hop/common"
	"hop.computer/hop/transport"

	"github.com/sirupsen/logrus"
)

// Unreliable implements UDP-like messages for Hop
type Unreliable struct {
	tType TubeType
	id    byte
	// outbound is owned by the Muxer; Unreliable cannot access or close its raw
	// queues.
	outbound *outbox

	// Unreliable tubes can be in three states:
	// created: Indicates the tube has been created and is waiting for the remote peer send back an initiate frame
	// initiated: Indicates the tube is ready to read and write data
	// closed: Indicates the tube is done reading and writing data
	state atomic.Value
	// lifecycleMu orders Close with initiation and packet admission. Producers
	// recheck state while holding it, so FIN is last and late receives are
	// rejected; Close separately joins the sender before publishing completion.
	lifecycleMu sync.Mutex
	// initiated publishes receipt of the peer's initiation frame.
	initiated chan struct{}
	// initiateDone publishes termination of the initiation producer.
	initiateDone chan struct{}
	// stopInitiate stops a locally initiated handshake without publishing Close
	// completion early.
	stopInitiate chan struct{}
	// senderDone publishes that every queued frame was handed to the Muxer.
	senderDone chan struct{}
	// closed publishes completion of Close, including the sender drain.
	closed chan struct{}

	// recv contains frames accepted from the Muxer but not returned to a reader.
	recv *common.DeadlineChan[[]byte]
	// send contains messages accepted from writers but not handed to the Muxer.
	send *common.DeadlineChan[[]byte]

	frameNo atomic.Uint32 // +checklocks:lifecycleMu
	// +checklocks:lifecycleMu
	finishFrame []byte

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

// sender drains messages admitted before Close and then admits FIN. It never
// holds lifecycleMu while the Muxer outbox can block.
func (u *Unreliable) sender() {
	defer close(u.senderDone)
	for {
		b, err := u.send.RecvQueued()
		if err != nil {
			break
		}
		u.log.Trace("handing packet to muxer")
		if err := u.outbound.enqueue(outboundFrame{bytes: b}, nil); err != nil {
			go u.Close()
			return
		}
	}

	u.lifecycleMu.Lock()
	finishFrame := u.finishFrame
	u.lifecycleMu.Unlock()
	if finishFrame != nil {
		if err := u.outbound.enqueue(outboundFrame{bytes: finishFrame}, nil); err != nil {
			go u.Close()
			return
		}
	}
	u.log.Debug("sender ended")
}

func (u *Unreliable) makeInitFrame(req bool) initiateFrame {
	return initiateFrame{
		tubeID:     u.id,
		tubeType:   u.tType,
		data:       []byte{},
		dataLength: 0,
		frameNo:    0,
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
		ticker := time.NewTicker(initialRTT)
		defer ticker.Stop()
	initLoop:
		for {
			u.lifecycleMu.Lock()
			state := u.state.Load()
			u.lifecycleMu.Unlock()
			switch state {
			case initiated:
				break initLoop
			case created:
				p := u.makeInitFrame(req)
				if err := u.outbound.enqueue(outboundFrame{bytes: p.toBytes()}, u.stopInitiate); err != nil {
					close(u.senderDone)
					return
				}
			default:
				close(u.senderDone)
				return
			}

			select {
			case <-ticker.C:
				u.log.Info("init rto exceeded")
			case <-u.initiated:
			case <-u.stopInitiate:
				close(u.senderDone)
				return
			}
		}
	} else {
		// The Muxer starts responder initiation before it dispatches the peer's
		// request. Wait for that request instead of racing the receiver and
		// permanently exiting the sender when this goroutine runs first.
		select {
		case <-u.initiated:
		case <-u.stopInitiate:
			close(u.senderDone)
			return
		}
	}

	u.lifecycleMu.Lock()
	started := u.state.Load() == initiated
	u.lifecycleMu.Unlock()
	if !started {
		close(u.senderDone)
		return
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
		"state":   u.state.Load(),
	}).Debug("receiving initiate packet")

	u.lifecycleMu.Lock()
	if u.state.Load() == created {
		u.state.Store(initiated)
		close(u.initiated)
	}

	// Send a RESP packet in response to REQ packets
	var response []byte
	if pkt.flags.REQ && u.state.Load() != closed {
		u.log.Trace("handing RESP packet to muxer")
		p := u.makeInitFrame(false)
		response = p.toBytes()
	}
	u.lifecycleMu.Unlock()

	if response != nil {
		return u.outbound.enqueue(outboundFrame{bytes: response}, u.stopInitiate)
	}

	return nil
}

func (u *Unreliable) receive(pkt *frame) error {
	if u.state.Load() == closed {
		return ErrBadTubeState
	}

	if !u.recv.TrySend(pkt.data) {
		return nil
	}
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

// WriteMsgUDP queues one message for the Unreliable sender. It may return before
// the message is handed to the Muxer or written to the transport. oob and addr
// are ignored.
func (u *Unreliable) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	select {
	case <-u.initiated:
		break
	case <-u.closed:
		break
	}

	u.lifecycleMu.Lock()
	if u.state.Load() == closed {
		u.lifecycleMu.Unlock()
		return 0, 0, io.EOF
	}

	dataLength := uint16(len(b))
	if uint16(len(b)) > MaxFrameDataLength {
		u.lifecycleMu.Unlock()
		err = transport.ErrBufOverflow
		return n, oobn, err
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
		queued:     false,
	}
	u.frameNo.Add(1)
	u.lifecycleMu.Unlock()

	err = u.send.Send(pkt.toBytes())
	if err != nil {
		return n, oobn, err
	}
	n = len(b)
	u.log.WithFields(logrus.Fields{
		"frameNo":    pkt.frameNo,
		"dataLength": pkt.dataLength,
	}).Trace("queued packet")
	return n, 0, err
}

// Close rejects new packets, places FIN after accepted writes, and waits until
// the sender hands its queue to the Muxer. It does not wait for transport writes
// or peer receipt. Future operations return io.EOF after buffered reads drain.
func (u *Unreliable) Close() error {
	u.lifecycleMu.Lock()
	oldState := u.state.Swap(closed)
	if oldState == closed {
		u.lifecycleMu.Unlock()
		return io.EOF
	}
	if oldState == initiated {
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
			queued:     false,
		}
		u.frameNo.Add(1)
		u.finishFrame = pkt.toBytes()
	}
	u.lifecycleMu.Unlock()

	if oldState == created {
		close(u.stopInitiate)
	}
	_ = u.send.Close()
	<-u.initiateDone

	<-u.senderDone

	_ = u.recv.Close()
	close(u.closed)

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
