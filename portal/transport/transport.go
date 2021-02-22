package transport

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
)

// SessionID is an IP-independent identifier of a tunnel.
type SessionID [4]byte

// SessionState contains the cryptographic state associated with a SessionID
// after the successful completion of a handshake.
type SessionState struct {
	sessionID SessionID

	m         sync.Mutex
	readLock  sync.Mutex
	writeLock sync.Mutex

	count             uint64
	clientToServerKey [KeyLen]byte
	serverToClientKey [KeyLen]byte
	remoteAddr        net.UDPAddr

	rawWrite bytes.Buffer
}

var emptyMac []byte

func init() {
	emptyMac = make([]byte, MacLen)
}

func PlaintextLen(transportLen int) int {
	return transportLen - HeaderLen - SessionIDLen - CounterLen - MacLen
}

func PeekSession(msg []byte) (out SessionID, err error) {
	if len(msg) < HeaderLen+SessionIDLen {
		err = ErrBufUnderflow
		return
	}
	copy(out[:], msg[HeaderLen:HeaderLen+SessionIDLen])
	return
}

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

func (ss *SessionState) lockUser() {
	ss.m.Lock()
	ss.writeLock.Lock()
	ss.readLock.Lock()
}

func (ss *SessionState) unlockUser() {
	ss.m.Unlock()
	ss.readLock.Unlock()
	ss.writeLock.Unlock()
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

func (ss *SessionState) writePacket(conn *net.UDPConn, in []byte, key *[KeyLen]byte) error {
	length := HeaderLen + SessionIDLen + CounterLen + len(in) + MacLen
	ss.rawWrite.Reset()
	if ss.rawWrite.Len() < length {
		ss.rawWrite.Grow(length)
	}

	ss.rawWrite.WriteByte(MessageTypeTransport)
	ss.rawWrite.WriteByte(0)
	ss.rawWrite.WriteByte(0)
	ss.rawWrite.WriteByte(0)

	// SessionID
	ss.rawWrite.Write(ss.sessionID[:])

	// Counter
	ss.writeCounter(&ss.rawWrite)
	logrus.Debugf("ss: wrote packet with count %d", ss.count)

	// TODO(dadrian): Encryption
	ss.rawWrite.Write(in)

	// TODO(dadrian): Mac Generation
	ss.rawWrite.Write(emptyMac)

	var written int
	written, _, err := conn.WriteMsgUDP(ss.rawWrite.Bytes(), nil, &ss.remoteAddr)
	if err != nil {
		return err
	}
	if written != length {
		logrus.Debugf("client: somehow wrote less than a message?")
		return errors.New("wat")
	}
	ss.count++
	return nil
}

func (ss *SessionState) readPacket(plaintext, pkt []byte, key *[KeyLen]byte) (int, error) {
	plaintextLen := PlaintextLen(len(pkt))
	if plaintextLen > len(plaintext) {
		return 0, ErrBufOverflow
	}

	// Header
	b := pkt
	if b[0] != MessageTypeTransport {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, ErrInvalidMessage
	}
	b = b[HeaderLen:]

	// SessionID
	if !bytes.Equal(ss.sessionID[:], b[:SessionIDLen]) {
		return 0, ErrUnknownSession
	}
	b = b[SessionIDLen:]

	// Counter
	count := ss.readCounter(b)
	logrus.Debugf("ss: read packet with count %d", count)
	b = b[CounterLen:]

	// TODO(dadrian): Decryption
	copy(plaintext, b[:plaintextLen])
	b = b[plaintextLen:]

	// TODO(dadrian): Mac Verify
	b = b[MacLen:]

	return plaintextLen, nil
}
