package portal

import (
	"bytes"
	"errors"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
	"zmap.io/portal/cyclist"
)

// Enforce ClientConn implements net.Conn
var _ net.Conn = &ClientConn{}

type ClientConn struct {
	underlyingConn *net.UDPConn
	duplex         cyclist.Cyclist
	publicDH       PublicDH
	ephemeral      X25519KeyPair
	static         X25519KeyPair
	buf            []byte
	pos            int

	encBuf []byte

	macBuf       [MacLen]byte
	handshakeKey [KeyLen]byte

	es []byte
	se []byte

	sessionID  [SessionIDLen]byte
	sessionKey [KeyLen]byte

	handshakeFn func() error
}

// Version is the protocol version being used. Only one version is supported.
const Version byte = 0x01

const HeaderLen = 4
const MacLen = 16
const KeyLen = 16
const DHLen = curve25519.PointSize
const CookieLen = 32 + 16 + 12
const SNILen = 256
const SessionIDLen = 4
const CounterLen = 8

// TODO(dadrian): Verify this
const MaxTotalPacketSize = 65535 - 18

// ProtocolName is the string representation of the parameters used in this version
const ProtocolName = "noise_NN_XX_cyclist_keccak_p1600_12"

var ErrBufOverflow = errors.New("write would overflow buffer")
var ErrBufUnderflow = errors.New("read would be past end of buffer")
var ErrUnexpectedMessage = errors.New("attempted to deserialize unexpected message type")
var ErrUnsupportedVersion = errors.New("unsupported version")
var ErrInvalidMessage = errors.New("invalid message")
var ErrUnknownSession = errors.New("unknown session")
var ErrUnknown = errors.New("unknown")

// Handshake performs the Portal handshake with the remote host. The connection
// must already be open. It is an error to call Handshake on a connection that
// has already performed the portal handshake.
func (c *ClientConn) Handshake() error {
	c.buf = make([]byte, 1024*1024)
	c.encBuf = make([]byte, len(c.buf))
	c.pos = 0
	return c.handshakeFn()
}

func (c *ClientConn) initializeKeyMaterial() {
	c.ephemeral.Generate()
	// TODO(dadrian): This should actually be, well, static
	c.static.Generate()
	c.duplex.InitializeEmpty()
	c.duplex.Absorb([]byte(ProtocolName))
}

func (c *ClientConn) clientHandshake() error {
	c.initializeKeyMaterial()
	clientHello := ClientHello{
		Ephemeral: c.ephemeral.public[:],
	}
	logrus.Debugf("c.ephemeral: %x", c.ephemeral)
	logrus.Debugf("clientHello: %v", clientHello)
	n, err := clientHello.serialize(c.buf[c.pos:])
	if err != nil {
		c.pos = 0
		return err
	}
	c.pos += n
	c.duplex.Absorb(c.buf[0:HeaderLen])
	c.duplex.Absorb(c.ephemeral.public[:])
	c.duplex.Squeeze(c.buf[c.pos : c.pos+MacLen])
	c.pos += MacLen
	n, err = c.underlyingConn.Write(c.buf[0:c.pos])
	if err != nil {
		return err
	}
	c.pos = 0
	n, err = c.underlyingConn.Read(c.buf[c.pos:])
	if err != nil {
		return err
	}
	logrus.Info(n, c.buf[0:n])
	if n < 4 {
		return ErrInvalidMessage
	}
	c.duplex.Absorb(c.buf[:4])
	sh := ServerHello{}
	mn, err := sh.deserialize(c.buf)
	if err != nil {
		return err
	}
	logrus.Info(sh)
	if mn+MacLen != n {
		return ErrInvalidMessage
	}
	c.duplex.Absorb(sh.Ephemeral)
	ephemeralSecret, err := c.ephemeral.DH(sh.Ephemeral)
	logrus.Debugf("client shared secret: %x", ephemeralSecret)
	if err != nil {
		return err
	}
	c.duplex.Absorb(ephemeralSecret)
	c.duplex.Absorb(sh.Cookie)
	c.duplex.Squeeze(c.handshakeKey[:])
	c.duplex.Squeeze(c.macBuf[:])
	if !bytes.Equal(c.macBuf[:], c.buf[mn:mn+MacLen]) {
		return ErrInvalidMessage
	}
	logrus.Debugf("client: sh mac: %x", c.macBuf)
	// TODO(dadrian): This needs to go through a KDF?
	c.duplex.Initialize(c.handshakeKey[:], []byte(ProtocolName), nil)
	c.duplex.Absorb([]byte{MessageTypeClientAck, 0, 0, 0})
	c.duplex.Absorb(c.ephemeral.public[:])
	c.duplex.Absorb(sh.Cookie)
	encryptedSNI, err := EncryptSNI("david.test", &c.duplex)
	if err != nil {
		return err
	}
	clientAck := ClientAck{
		Ephemeral:    c.ephemeral.public[:],
		Cookie:       sh.Cookie,
		EncryptedSNI: encryptedSNI,
	}
	c.pos = 0
	n, err = clientAck.serialize(c.buf)
	if err != nil {
		return err
	}
	c.duplex.Squeeze(c.buf[n : n+MacLen])
	n, err = c.underlyingConn.Write(c.buf[:n+MacLen])
	if err != nil {
		return err
	}
	msgLen, err := c.underlyingConn.Read(c.buf)
	if err != nil {
		return err
	}
	logrus.Debugf("clinet: sa msgLen: %d", msgLen)
	if msgLen < HeaderLen+SessionIDLen {
		return ErrBufUnderflow
	}
	x := c.buf
	if x[0] != MessageTypeServerAuth {
		return ErrInvalidMessage
	}
	var encCertLen int
	encCertLen = (int(x[2]) << 8) + int(x[3])
	c.duplex.Absorb(x[:HeaderLen])
	x = x[HeaderLen:]
	copy(c.sessionID[:], x[:SessionIDLen])
	c.duplex.Absorb(x[:SessionIDLen])
	x = x[SessionIDLen:]
	if len(x) < encCertLen {
		logrus.Debug("client: no room for certs")
		return ErrBufUnderflow
	}
	leaf, intermediate, err := DecryptCertificates(&c.duplex, x[:encCertLen])
	if err != nil {
		logrus.Debug("client: no decrypt certs")
		return err
	}
	logrus.Debugf("client leaft, inter: %x, %x", leaf, intermediate)
	x = x[encCertLen:]
	if len(x) < 2*MacLen {
		logrus.Debug("client: no room for sa macs")
		return ErrBufUnderflow
	}
	c.duplex.Squeeze(c.macBuf[:])
	logrus.Debugf("client: sa tag: %x", c.macBuf)
	if !bytes.Equal(c.macBuf[:], x[:MacLen]) {
		logrus.Debug("client: sa tag mismatch")
	}
	x = x[MacLen:]
	c.es, err = c.ephemeral.DH(leaf)
	if err != nil {
		logrus.Debug("client: couldn't do es")
		return err
	}
	logrus.Debugf("client: es %x", c.es)
	c.duplex.Absorb(c.es)
	c.duplex.Squeeze(c.macBuf[:])
	logrus.Debugf("client: sa mac %x", c.macBuf[:])
	if !bytes.Equal(c.macBuf[:], x[:MacLen]) {
		logrus.Debug("client: mismatched sa mac")
		return err
	}
	// Client Auth
	c.pos = 0
	b := c.buf
	b[0] = MessageTypeClientAuth
	b[1] = 0
	b[2] = 0
	b[3] = 0
	c.duplex.Absorb(b[0:4])
	b = b[4:]
	c.pos += 4
	copy(b, c.sessionID[:])
	c.duplex.Absorb(c.sessionID[:])
	b = b[SessionIDLen:]
	c.pos += SessionIDLen
	c.duplex.Encrypt(b[:DHLen], c.static.public[:])
	b = b[DHLen:]
	c.pos += DHLen
	c.duplex.Squeeze(b[:MacLen]) // tag
	b = b[MacLen:]
	c.pos += MacLen
	c.se, err = c.static.DH(sh.Ephemeral)
	if err != nil {
		logrus.Errorf("client: unable to calc se: %s", err)
		return err
	}
	logrus.Debugf("client: se %x", c.se)
	c.duplex.Absorb(c.se)
	c.duplex.Squeeze(b[:MacLen]) // mac
	b = b[MacLen:]
	c.pos += MacLen
	n, err = c.underlyingConn.Write(c.buf[0:c.pos])
	if err != nil {
		logrus.Errorf("client: unable to send client auth: %s", err)
		return err
	}
	return nil
}

func (c *ClientConn) Write(b []byte) (n int, err error) {
	return
}

func (c *ClientConn) Close() error {
	return nil
}

func (c *ClientConn) Read(b []byte) (n int, err error) {
	return
}

func (c *ClientConn) LocalAddr() net.Addr {
	return c.underlyingConn.LocalAddr()
}

func (c *ClientConn) RemoteAddr() net.Addr {
	return c.underlyingConn.RemoteAddr()
}

func (c *ClientConn) SetDeadline(t time.Time) error {
	return c.underlyingConn.SetDeadline(t)
}

func (c *ClientConn) SetReadDeadline(t time.Time) error {
	return c.underlyingConn.SetReadDeadline(t)
}

func (c *ClientConn) SetWriteDeadline(t time.Time) error {
	return c.underlyingConn.SetWriteDeadline(t)
}

func Client(conn *net.UDPConn, config *Config) *ClientConn {
	c := &ClientConn{
		underlyingConn: conn,
	}
	c.handshakeFn = c.clientHandshake
	return c
}
