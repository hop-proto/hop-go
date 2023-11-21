package transport

import (
	"bytes"
	"io"
	"net"
	"sync"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/kravatte"
	"hop.computer/hop/common"
)

// SessionID is an IP-independent identifier of a tunnel.
type SessionID [4]byte

// SessionState contains the cryptographic state associated with a SessionID
// after the successful completion of a handshake.
type SessionState struct {
	sessionID SessionID

	// Constant after handshake
	clientToServerKey [KeyLen]byte
	serverToClientKey [KeyLen]byte
	handle            *Handle
	readKey, writeKey *[KeyLen]byte

	// TODO(dadrian)[2023-09-09]: Should this be lock protected?
	rawWrite bytes.Buffer

	m sync.Mutex

	// +checklocks:m
	handleState connState
	remoteAddr  *net.UDPAddr
	window      SlidingWindow
	count       uint64
}

// PlaintextLen returns the expected length of plaintext given the length of a
// transport message. It returns a negative number for transport messages of
// insufficient length to contain any plaintext.
func PlaintextLen(transportLen int) int {
	return transportLen - HeaderLen - SessionIDLen - CounterLen - TagLen
}

// PeekSession returns the SessionID located in the provided raw transport
// message. It errors if the buffer is too short.
func PeekSession(msg []byte) (out SessionID, err error) {
	if len(msg) < HeaderLen+SessionIDLen {
		err = ErrBufUnderflow
		return
	}
	copy(out[:], msg[HeaderLen:HeaderLen+SessionIDLen])
	return
}

// EqualUDPAddress returns true if the two net.UDPAddrs have the same IP, Port,
// and Zone.
func EqualUDPAddress(a, b *net.UDPAddr) bool {
	if a.Port != b.Port {
		return false
	}
	if !a.IP.Equal(b.IP) {
		return false
	}
	if a.Zone != b.Zone {
		return false
	}
	return true
}

func (ss *SessionState) writeCounter(w io.ByteWriter) {
	w.WriteByte(byte(ss.count >> 56))
	w.WriteByte(byte(ss.count >> 48))
	w.WriteByte(byte(ss.count >> 40))
	w.WriteByte(byte(ss.count >> 32))
	w.WriteByte(byte(ss.count >> 24))
	w.WriteByte(byte(ss.count >> 16))
	w.WriteByte(byte(ss.count >> 8))
	w.WriteByte(byte(ss.count))
}

func (ss *SessionState) readCounter(b []byte) (count uint64) {
	_ = b[7]
	count += uint64(b[0]) << 56
	count += uint64(b[1]) << 48
	count += uint64(b[2]) << 40
	count += uint64(b[3]) << 32
	count += uint64(b[4]) << 24
	count += uint64(b[5]) << 16
	count += uint64(b[6]) << 8
	count += uint64(b[7])
	return
}

func (ss *SessionState) writePacketLocked(conn UDPLike, msgType MessageType, in []byte, key *[KeyLen]byte) error {
	length := HeaderLen + SessionIDLen + CounterLen + len(in) + TagLen
	ss.rawWrite.Reset()
	if ss.rawWrite.Cap() < length {
		ss.rawWrite.Grow(length)
	}

	ss.rawWrite.WriteByte(byte(msgType))
	ss.rawWrite.WriteByte(0)
	ss.rawWrite.WriteByte(0)
	ss.rawWrite.WriteByte(0)

	// SessionID
	ss.rawWrite.Write(ss.sessionID[:])

	// Counter
	ss.writeCounter(&ss.rawWrite)
	if common.Debug {
		logrus.Tracef("ss: writing packet with count %d", ss.count)
	}

	// Encrypt the message. The associated data is the message header. There is
	// no nonce. The output has an overhead of TagLength.
	aead, err := kravatte.NewSANSE(key[:])
	if err != nil {
		return err
	}
	buf := make([]byte, TagLen+len(in))
	enc := aead.Seal(buf[:0], nil, in, ss.rawWrite.Bytes()[:AssociatedDataLen])
	if common.Debug {
		logrus.Tracef("write: %x %x", buf[:12], enc)
		logrus.Tracef("write(buf): %x", buf)
	}
	if len(enc) != len(buf) {
		logrus.Panicf("expected len(buf) = len(enc), got: %d = %d + 12", len(buf), len(enc))
	}
	ss.rawWrite.Write(buf)

	b := ss.rawWrite.Bytes()
	written, _, err := conn.WriteMsgUDP(b, nil, ss.remoteAddr)
	if err != nil {
		return err
	}
	if written != length {
		// Should never happen
		logrus.Panicf("WriteMsgUDP wrote %d, expected length %d", written, length)
	}
	ss.count++
	return nil
}

func (ss *SessionState) readPacketLocked(plaintext, pkt []byte, key *[KeyLen]byte) (int, MessageType, error) {
	plaintextLen := PlaintextLen(len(pkt))
	ciphertextLen := plaintextLen + TagLen
	if plaintextLen > len(plaintext) {
		return 0, 0x0, ErrBufOverflow
	}

	// Header
	b := pkt
	var mt MessageType
	if mt = MessageType(b[0]); mt != MessageTypeTransport && mt != MessageTypeControl {
		return 0, 0x0, ErrUnexpectedMessage
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, 0x0, ErrInvalidMessage
	}
	b = b[HeaderLen:]

	// SessionID
	if !bytes.Equal(ss.sessionID[:], b[:SessionIDLen]) {
		return 0, 0x0, ErrUnknownSession
	}
	b = b[SessionIDLen:]

	// Counter
	count := ss.readCounter(b)
	if common.Debug {
		logrus.Tracef("ss: read packet with count %d", count)
	}
	if !ss.window.Check(count) {
		logrus.Debugf("ss: rejecting replayed packet")
		return 0, 0x0, ErrReplay
	}
	b = b[CounterLen:]

	aead, err := kravatte.NewSANSE(key[:])
	if err != nil {
		return 0, 0x0, err
	}
	enc := b[:ciphertextLen]
	if common.Debug {
		logrus.Tracef("read enc: %x", enc)
	}
	b = b[ciphertextLen:]
	if len(b) != 0 {
		logrus.Panicf("len(b) = %d, expected 0", len(b))
	}
	out, err := aead.Open(plaintext[:0], nil, enc, pkt[:AssociatedDataLen])
	if err != nil {
		return 0, 0x0, err
	}
	if len(out) != plaintextLen {
		logrus.Panicf("len(out) = %d, expected plaintextLen = %d", len(out), plaintextLen)
	}
	ss.window.Mark(count)

	return plaintextLen, mt, nil
}

func (ss *SessionState) handleControlLocked(msg []byte) (err error) {
	if len(msg) != 1 {
		logrus.Error("handle: invalid control message: ", msg)
		ss.closeLocked()
		return ErrInvalidMessage
	}

	ctrlMsg := ControlMessage(msg[0])
	switch ctrlMsg {
	case ControlMessageClose:
		logrus.Debug("handle: got close message")
		return ss.closeLocked()
	default:
		logrus.Errorf("server: unexpected control message: %x", msg)
		ss.closeLocked()
		return ErrInvalidMessage
	}
}

func (ss *SessionState) closeLocked() (err error) {
	if ss.handleState == closed {
		return nil
	}
	// TODO(dadrian)[2023-09-09]: Actually close. This is hard because sometimes
	// the Server knows we're closing, and sometimes only the Handle knows.
	return nil
}
