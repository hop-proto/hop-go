package portal

import (
	"errors"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/cyclist"
)

// MessageType is a single-byte-wide enum used as the first byte of every message. It can be used to differentiate message types.
type MessageType byte

// MessageType constants for each type of handshake and transport message.
const (
	MessageTypeClientHello MessageType = 0x01
	MessageTypeServerHello             = 0x02
	MessageTypeClientAck               = 0x03
	MessageTypeServerAuth              = 0x04
	MessageTypeClientAuth              = 0x05
	MessageTypeTransport               = 0x10
)

// IsHandshakeType returns true if the message type is part of the handshake, not the transport.
func (mt MessageType) IsHandshakeType() bool { return (byte(mt) & byte(0x0F)) != 0 }

type ClientHello struct {
	Ephemeral []byte
}

func serializeToHello(duplex *cyclist.Cyclist, b []byte, keyPair *X25519KeyPair) (int, error) {
	if len(b) < HelloLen {
		return 0, ErrBufOverflow
	}
	// Header
	b[0] = byte(MessageTypeClientHello) // Type = ClientHello (0x01)
	b[1] = Version                      // Version
	b[2] = 0                            // Reserved
	b[3] = 0                            // Reserved
	duplex.Absorb(b[0:4])

	// Ephemeral
	copy(b[4:], keyPair.public[:])
	duplex.Absorb(keyPair.public[:])

	return HelloLen, nil
}

func (m *ClientHello) deserialize(b []byte) (int, error) {
	if len(b) < HeaderLen+DHLen {
		return 0, ErrBufUnderflow
	}
	if MessageType(b[0]) != MessageTypeClientHello {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != Version {
		return 0, ErrUnsupportedVersion
	}
	// TODO(dadrian): Should we check if reserved fields are zero?
	// TODO(dadrian): Avoid allocation?
	m.Ephemeral = make([]byte, DHLen)
	b = b[4:]
	copy(m.Ephemeral, b[:DHLen])
	b = b[DHLen:]
	return 4 + DHLen, nil
}

type ServerHello struct {
	Ephemeral []byte
	Cookie    []byte
}

func (m *ServerHello) serialize(b []byte) (int, error) {
	if len(b) < HeaderLen+DHLen+len(m.Cookie) {
		return 0, ErrBufOverflow
	}
	x := b
	x[0] = MessageTypeServerHello
	x[1] = 0
	x[2] = 0
	x[3] = 0
	x = x[4:]
	n := copy(x[0:DHLen], m.Ephemeral)
	if n != DHLen {
		return 0, ErrInvalidMessage
	}
	x = x[DHLen:]
	n = copy(x, m.Cookie)
	if n != len(m.Cookie) {
		return 0, ErrBufOverflow
	}
	return 4 + DHLen + n, nil
}

func (m *ServerHello) deserialize(b []byte) (int, error) {
	if len(b) < HeaderLen+DHLen+CookieLen {
		return 0, ErrBufOverflow
	}
	x := b
	if MessageType(x[0]) != MessageTypeServerHello {
		return 0, ErrUnexpectedMessage
	}
	x = x[4:]
	// TODO(dadrian): Should we check if reserved fields are zero?
	m.Ephemeral = make([]byte, DHLen)
	n := copy(m.Ephemeral, x[:DHLen])
	if n != DHLen {
		return 0, ErrInvalidMessage
	}
	x = x[DHLen:]
	m.Cookie = make([]byte, CookieLen)
	n = copy(m.Cookie, x[:CookieLen])
	if n != CookieLen {
		return 0, ErrInvalidMessage
	}
	return 4 + DHLen + CookieLen, nil
}

type ClientAck struct {
	Ephemeral    []byte
	Cookie       []byte
	EncryptedSNI []byte
}

func (m *ClientAck) serialize(b []byte) (int, error) {
	length := HeaderLen + DHLen + CookieLen + SNILen
	if len(b) < length {
		return 0, ErrBufOverflow
	}
	x := b
	pos := 0
	x[0] = MessageTypeClientAck
	x[1] = 0
	x[2] = 0
	x[3] = 0
	x = x[4:]
	pos += 4
	n := copy(x, m.Ephemeral)
	pos += n
	if n != DHLen {
		return pos, ErrInvalidMessage
	}
	x = x[DHLen:]
	n = copy(x, m.Cookie)
	pos += n
	if n != CookieLen {
		return pos, ErrInvalidMessage
	}
	x = x[CookieLen:]
	n = copy(x, m.EncryptedSNI)
	pos += n
	if n != SNILen {
		return pos, ErrInvalidMessage
	}
	return pos, nil
}

func (m *ClientAck) deserialize(b []byte) (int, error) {
	length := HeaderLen + DHLen + CookieLen + SNILen
	if len(b) < length {
		return 0, ErrBufUnderflow
	}
	x := b
	pos := 0
	if x[0] != MessageTypeClientAck {
		return pos, ErrUnexpectedMessage
	}
	x = x[HeaderLen:]
	pos += HeaderLen
	m.Ephemeral = make([]byte, DHLen)
	n := copy(m.Ephemeral, x[:DHLen])
	if n != DHLen {
		logrus.Debug("bad DH in clientack")
		return 0, ErrInvalidMessage
	}
	x = x[DHLen:]
	pos += DHLen
	m.Cookie = make([]byte, CookieLen)
	n = copy(m.Cookie, x[:CookieLen])
	if n != CookieLen {
		logrus.Debug("bad cookie in clientack")
		return 0, ErrInvalidMessage
	}
	x = x[CookieLen:]
	pos += CookieLen
	m.EncryptedSNI = make([]byte, SNILen)
	n = copy(m.EncryptedSNI, x[:SNILen])
	if n != SNILen {
		logrus.Debug("bad SNI in clientack", n)
		return 0, ErrInvalidMessage
	}
	pos += n
	return pos, nil
}

// TODO(dadrian): Avoid allocation
func EncryptSNI(name string, duplex *cyclist.Cyclist) ([]byte, error) {
	buf := make([]byte, SNILen)
	nameLen := len(name)
	if nameLen > 255 {
		return nil, errors.New("invalid SNI name")
	}
	buf[0] = byte(nameLen)
	n := copy(buf[1:], name)
	if n != nameLen {
		return nil, errors.New("invalid SNI name")
	}
	for i := n; i < SNILen; i++ {
		buf[i] = 0
	}
	// TODO(dadrian): Remove allocation
	enc := make([]byte, SNILen)
	duplex.Encrypt(enc, buf)
	return enc, nil
}

func writeVector(dst []byte, src []byte) (int, error) {
	srcLen := len(src)
	if srcLen > 65535 {
		return 0, errors.New("input too long for vector")
	}
	if len(dst) < 2+srcLen {
		return 0, errors.New("dst too short")
	}
	dst[0] = byte(srcLen >> 8)
	dst[1] = byte(srcLen)
	copy(dst[2:], src)
	return 2 + srcLen, nil
}

func readVector(src []byte) (int, []byte, error) {
	srcLen := len(src)
	if srcLen < 2 {
		return 0, nil, ErrBufUnderflow
	}
	vecLen := (int(src[0]) << 8) + int(src[1])
	end := 2 + vecLen
	if srcLen < end {
		return 0, nil, ErrBufUnderflow
	}
	return vecLen, src[2:end], nil
}
