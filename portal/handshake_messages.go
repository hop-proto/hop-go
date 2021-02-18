package portal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"net"

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

// HandshakeState tracks state across the lifetime of a handshake, starting with
// the ClientHello. A HandshakeState may be allocated on ClientHello, it does
// not need to be stored until after the ClientAck since enough state is
// contained within the cookie to reconstruct the HandshakeState.
type HandshakeState struct {
	duplex    cyclist.Cyclist
	ephemeral X25519KeyPair
	static    *X25519KeyPair

	macBuf          [MacLen]byte
	remoteEphemeral [DHLen]byte
	handshakeKey    [KeyLen]byte
	clientStatic    [DHLen]byte
	sessionID       [SessionIDLen]byte

	cookieKey *[KeyLen]byte // server only

	cookie []byte // client only

	// TODO(dadrian): Rework APIs to make these arrays and avoid copies with the curve25519 API.
	ee []byte
	es []byte
	se []byte

	remoteAddr *net.UDPAddr
}

func (hs *HandshakeState) writeCookie(b []byte) (int, error) {
	// TODO(dadrian): Avoid allocating memory. Store a cipher on HandshakeState,
	// but only if cipher.Block is thread-safe. But not sure how we'd avoid
	// allocating memory for the NewGCM call. Hopefully this can be avoided when
	// we switch to Kravatte.
	cookieCipher, err := aes.NewCipher(hs.cookieKey[:])
	if err != nil {
		return 0, err
	}
	aead, err := cipher.NewGCMWithTagSize(cookieCipher, 16)
	if err != nil {
		return 0, err
	}

	// Until we sort out Deck-SANE, just shove a nonce here
	if n, err := rand.Read(b[0:12]); err != nil || n != 12 {
		panic("could not read random for cookie")
	}
	nonce := b[0:12]
	plaintextCookie := hs.ephemeral.private[:]
	ad := CookieAD(&hs.remoteEphemeral, hs.remoteAddr)
	logrus.Debugf("encrypt: cookie ad: %x", ad)
	enc := aead.Seal(b[12:12], nonce, plaintextCookie, ad)
	return len(enc) + 12, nil // CookieLen
}

func (hs *HandshakeState) decryptCookie(b []byte) (int, error) {
	if len(b) < CookieLen {
		return 0, ErrBufUnderflow
	}
	cookieCipher, err := aes.NewCipher(hs.cookieKey[:])
	if err != nil {
		return 0, err
	}
	aead, err := cipher.NewGCMWithTagSize(cookieCipher, 16)
	if err != nil {
		return 0, err
	}
	nonce := b[0:12]
	encryptedCookie := b[12:CookieLen]
	ad := CookieAD(&hs.remoteEphemeral, hs.remoteAddr)
	logrus.Debugf("decrypt: cookie ad: %x", ad)
	// TODO(dadrian): Avoid allocation?
	out, err := aead.Open(hs.ephemeral.private[:0], nonce, encryptedCookie, ad)
	if len(out) != DHLen {
		return 0, ErrInvalidMessage
	}
	hs.ephemeral.PublicFromPrivate()
	return CookieLen, nil
}

func writeClientHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < HelloLen {
		return 0, ErrBufOverflow
	}
	x := b
	// Header
	x[0] = byte(MessageTypeClientHello) // Type = ClientHello (0x01)
	x[1] = Version                      // Version
	x[2] = 0                            // Reserved
	x[3] = 0                            // Reserved
	hs.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]

	// Ephemeral
	copy(x, hs.ephemeral.public[:])
	hs.duplex.Absorb(hs.ephemeral.public[:])
	x = x[DHLen:]

	// Mac
	hs.duplex.Squeeze(x[:MacLen])
	logrus.Debugf("client: client hello mac: %x", x[:MacLen])
	return HelloLen, nil
}

func readClientHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < HelloLen {
		return 0, ErrBufUnderflow
	}
	if MessageType(b[0]) != MessageTypeClientHello {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != Version {
		return 0, ErrUnsupportedVersion
	}
	if b[2] != 0 || b[3] != 0 {
		return 0, ErrInvalidMessage
	}
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]
	copy(hs.remoteEphemeral[:], b[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]
	hs.duplex.Squeeze(hs.macBuf[:])
	// TODO(dadrian): #constanttime
	logrus.Debugf("server: calculated client hello mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		return 0, ErrInvalidMessage
	}
	return HelloLen, nil
}

func writeServerHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < HeaderLen+DHLen+CookieLen+MacLen {
		return 0, ErrBufOverflow
	}

	// Header
	b[0] = MessageTypeServerHello
	b[1] = 0
	b[2] = 0
	b[3] = 0
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// Ephemeral
	copy(b, hs.ephemeral.public[:])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]

	secret, err := hs.ephemeral.DH(hs.remoteEphemeral[:])
	if err != nil {
		return 0, err
	}
	hs.duplex.Absorb(secret)

	// Cookie
	n, err := hs.writeCookie(b)
	logrus.Debugf("server: generated cookie %x", b[:n])
	if err != nil {
		return 0, err
	}
	if n != CookieLen {
		return 0, ErrBufOverflow
	}
	hs.duplex.Absorb(b[:CookieLen])
	b = b[CookieLen:]

	// Mac
	hs.duplex.Squeeze(b[:MacLen])

	return HeaderLen + DHLen + CookieLen + MacLen, nil
}

func readServerHello(hs *HandshakeState, b []byte) (int, error) {
	if len(b) < HeaderLen+DHLen+CookieLen+MacLen {
		return 0, ErrBufOverflow
	}

	// Header
	if MessageType(b[0]) != MessageTypeServerHello {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, ErrInvalidMessage
	}
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// Server Ephemeral
	copy(hs.remoteEphemeral[:], b[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]
	secret, err := hs.ephemeral.DH(hs.remoteEphemeral[:])
	if err != nil {
		return 0, err
	}
	hs.duplex.Absorb(secret)

	// Cookie
	hs.cookie = make([]byte, CookieLen)
	copy(hs.cookie, b[:CookieLen])
	hs.duplex.Absorb(b[:CookieLen])
	logrus.Debugf("client: read cookie %x", hs.cookie)
	b = b[CookieLen:]

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: sh mac %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		return 0, ErrInvalidMessage
	}

	return HeaderLen + DHLen + CookieLen + MacLen, nil
}

func (hs *HandshakeState) RekeyFromSqueeze() {
	hs.duplex.Squeeze(hs.handshakeKey[:])
	hs.duplex.Initialize(hs.handshakeKey[:], []byte(ProtocolName), nil)
}

func (hs *HandshakeState) EncryptSNI(dst []byte, name string) error {
	var buf [SNILen]byte
	if len(dst) < SNILen {
		return ErrBufUnderflow
	}
	nameLen := len(name)
	if nameLen > 255 {
		return errors.New("invalid SNI name")
	}
	buf[0] = byte(nameLen)
	n := copy(buf[1:], name)
	if n != nameLen {
		return errors.New("invalid SNI name")
	}
	hs.duplex.Encrypt(dst, buf[:])
	return nil
}

func (hs *HandshakeState) writeClientAck(b []byte, name string) (int, error) {
	length := HeaderLen + DHLen + CookieLen + SNILen + MacLen
	if len(b) < length {
		return 0, ErrBufOverflow
	}

	// Header
	b[0] = MessageTypeClientAck
	b[1] = 0
	b[2] = 0
	b[3] = 0
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// DH
	copy(b, hs.ephemeral.public[:DHLen])
	hs.duplex.Absorb(b[:DHLen])
	b = b[DHLen:]

	// Cookie
	n := copy(b, hs.cookie)
	if n != CookieLen {
		logrus.Debugf("unexpected cookie length: %d (expected %d)", n, CookieLen)
		return HeaderLen + DHLen + n, ErrInvalidMessage
	}
	hs.duplex.Absorb(b[:CookieLen])
	b = b[CookieLen:]

	// Encrypted SNI
	copy(b, "lol no SNI yet")
	err := hs.EncryptSNI(b, name)
	if err != nil {
		return HeaderLen + DHLen + CookieLen, ErrInvalidMessage
	}
	b = b[SNILen:]

	// Mac
	hs.duplex.Squeeze(b[:MacLen])
	b = b[MacLen:]

	return length, nil
}

func (hs *HandshakeState) readServerAuth(b []byte) (int, error) {
	minLength := HeaderLen + SessionIDLen + 2*MacLen
	if len(b) < minLength {
		return 0, ErrBufUnderflow
	}

	// Header
	if b[0] != MessageTypeServerAuth {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != 0 {
		return 0, ErrInvalidMessage
	}
	// TODO(dadrian): Should we just get this out of UDP packet length?
	encryptedCertLen := (int(b[2]) << 8) + int(b[3])
	logrus.Debugf("client: got encrypted cert length %d", encryptedCertLen)
	fullLength := minLength + encryptedCertLen
	if len(b) < fullLength {
		return 0, ErrBufOverflow
	}
	hs.duplex.Absorb(b[:HeaderLen])
	b = b[HeaderLen:]

	// SessionID
	copy(hs.sessionID[:], b[:SessionIDLen])
	hs.duplex.Absorb(hs.sessionID[:])
	logrus.Debugf("client: got session ID %x", hs.sessionID)
	b = b[SessionIDLen:]

	// Certs
	encryptedCertificates := b[:encryptedCertLen]
	b = b[encryptedCertLen:]

	// Decrypt the certificates, but don't read them yet
	leaf, intermediate, err := DecryptCertificates(&hs.duplex, encryptedCertificates)
	if err != nil {
		logrus.Debugf("client: error decrypting certificates: %s", err)
		return 0, err
	}
	logrus.Debugf("client: leaf, intermediate: %x, %x", leaf, intermediate)

	// Tag (Encrypted Certs)
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: calculated sa tag: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("client: sa tag mismatch, got %x, wanted %x", b[:MacLen], hs.macBuf)
		return 0, ErrInvalidMessage
	}
	b = b[MacLen:]

	// DH
	// TODO(dadrian): Avoid this allocation?
	hs.es, err = hs.ephemeral.DH(leaf)
	if err != nil {
		logrus.Debugf("client: could not calculate es: %s", err)
		return 0, err
	}
	logrus.Debugf("client: es: %x", hs.es)
	hs.duplex.Absorb(hs.es)

	// Mac
	hs.duplex.Squeeze(hs.macBuf[:])
	logrus.Debugf("client: calculated sa mac: %x", hs.macBuf)
	if !bytes.Equal(hs.macBuf[:], b[:MacLen]) {
		logrus.Debugf("client: expected sa mac %x, got %x", hs.macBuf, b[:MacLen])
	}
	b = b[MacLen:]

	return fullLength, nil
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
