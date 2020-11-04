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

type Conn struct {
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

// ProtocolName is the string representation of the parameters used in this version
const ProtocolName = "noise_NN_XX_cyclist_keccak_p1600_12"

var ErrBufOverflow = errors.New("write would overflow buffer")
var ErrBufUnderflow = errors.New("read would be past end of buffer")
var ErrUnexpectedMessage = errors.New("attempted to deserialize unexpected message type")
var ErrUnsupportedVersion = errors.New("unsupported version")
var ErrInvalidMessage = errors.New("invalid message")
var ErrUnknown = errors.New("unknown")

// Handshake performs the Portal handshake with the remote host. The connection
// must already be open. It is an error to call Handshake on a connection that
// has already performed the portal handshake.
func (c *Conn) Handshake() error {
	c.buf = make([]byte, 1024*1024)
	c.encBuf = make([]byte, len(c.buf))
	c.pos = 0
	return c.handshakeFn()
}

func (c *Conn) initializeKeyMaterial() {
	c.ephemeral.Generate()
	// TODO(dadrian): This should actually be, well, static
	c.static.Generate()
	c.duplex.InitializeEmpty()
	c.duplex.Absorb([]byte(ProtocolName))
}

func (c *Conn) clientHandshake() error {
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
	c.duplex.Squeeze(c.macBuf[:])
	if !bytes.Equal(c.macBuf[:], c.buf[mn:mn+MacLen]) {
		return ErrInvalidMessage
	}
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
	return nil
}

func (c *Conn) serverHandshake() error {
	_, err := c.underlyingConn.Read(c.buf[c.pos : c.pos+4])
	if err != nil {
		return err
	}
	return nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	return
}

func (c *Conn) Close() error {
	return nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return
}

func (c *Conn) LocalAddr() net.Addr {
	return c.underlyingConn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.underlyingConn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.underlyingConn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.underlyingConn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.underlyingConn.SetWriteDeadline(t)
}

func Client(conn *net.UDPConn, config *Config) *Conn {
	c := &Conn{
		underlyingConn: conn,
	}
	c.handshakeFn = c.clientHandshake
	return c
}
