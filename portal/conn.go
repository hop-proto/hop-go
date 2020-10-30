package portal

import (
	"errors"
	"net"
	"time"

	"github.com/sirupsen/logrus"
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

	handshakeFn func() error
}

// Version is the protocol version being used. Only one version is supported.
const Version byte = 0x01

// ProtocolName is the string representation of the parameters used in this version
const ProtocolName = "noise_NN_XX_cyclist_keccak_p1600_12"

const macLen = 16

var ErrBufFull = errors.New("write would overflow buffer")

// Handshake performs the Portal handshake with the remote host. The connection
// must already be open. It is an error to call Handshake on a connection that
// has already performed the portal handshake.
func (c *Conn) Handshake() error {
	c.buf = make([]byte, 1024*1024)
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
	c.duplex.Absorb(c.buf[0:c.pos])
	c.duplex.Squeeze(c.buf[c.pos : c.pos+macLen])
	c.pos += macLen
	n, err = c.underlyingConn.Write(c.buf[0:c.pos])
	if err != nil {
		return err
	}
	c.pos = 0
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
