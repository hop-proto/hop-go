package transport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"

	"github.com/sirupsen/logrus"
)

// SessionID is an IP-independent identifier of a tunnel.
type SessionID [4]byte

// SessionState contains the cryptographic state associated with a SessionID
// after the successful completion of a handshake.
type SessionState struct {
	sessionID SessionID

	count             uint64
	clientToServerKey [KeyLen]byte
	serverToClientKey [KeyLen]byte
	remoteAddr        net.UDPAddr

	handle *Handle

	rawWrite bytes.Buffer
}

var emptyMac []byte

func init() {
	emptyMac = make([]byte, MacLen)
}

// PlaintextLen returns the expected length of plaintext given the length of a
// transport message. It returns a negative number for transport messages of
// insufficient length to contain any plaintext.
func PlaintextLen(transportLen int) int {
	// TODO(dadrian): remove the 12-byte nonce when we get rid of AES
	return transportLen - HeaderLen - SessionIDLen - CounterLen - MacLen - 12
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

func (ss *SessionState) writePacket(conn *net.UDPConn, in []byte, key *[KeyLen]byte) error {
	length := HeaderLen + SessionIDLen + CounterLen + len(in) + MacLen + 12
	ss.rawWrite.Reset()
	if ss.rawWrite.Cap() < length {
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
	logrus.Debugf("ss: writing packet with count %d", ss.count)

	// Temporary Encryption via AES until Kravatte is working
	// TODO(dadrian): Finish Kravatte and get rid of AES.
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCMWithTagSize(block, MacLen)
	if err != nil {
		return err
	}
	buf := make([]byte, 12+MacLen+len(in))
	if n, err := rand.Read(buf[0:12]); err != nil || n != 12 {
		panic("could not read random nonce for transport")
	}
	enc := aead.Seal(buf[12:12], buf[:12], in, []byte("oops all static"))
	logrus.Debugf("write: %x %x", buf[:12], enc)
	logrus.Debugf("write(buf): %x", buf)
	if len(enc)+12 != len(buf) {
		logrus.Panicf("expected len(buf) = len(enc) + 12, got: %d = %d + 12", len(buf), len(enc))
	}

	// TODO(dadrian): Encryption
	ss.rawWrite.Write(buf)

	b := ss.rawWrite.Bytes()
	written, _, err := conn.WriteMsgUDP(b, nil, &ss.remoteAddr)
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

func (ss *SessionState) readPacket(plaintext, pkt []byte, key *[KeyLen]byte) (int, error) {
	plaintextLen := PlaintextLen(len(pkt))
	ciphertextLen := plaintextLen + MacLen
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

	// Temporary Encryption via AES until Kravatte is working
	// TODO(dadrian): Finish Kravatte and get rid of AES.
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return 0, err
	}
	aead, err := cipher.NewGCMWithTagSize(block, MacLen)
	if err != nil {
		return 0, err
	}
	nonce := b[:12]
	b = b[12:]
	enc := b[:ciphertextLen]
	logrus.Debugf("read: %x %x", nonce, enc)
	out, err := aead.Open(plaintext[:0], nonce, enc, []byte("oops all static"))
	if err != nil {
		return 0, err
	}
	if len(out) != plaintextLen {
		panic("wtf mate")
	}
	b = b[plaintextLen:]
	b = b[MacLen:] // Mac checked as part of Open

	return plaintextLen, nil
}
