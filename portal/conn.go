package portal

import (
	"errors"
	"net"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/cyclist"
)

type Conn struct {
	underlyingConn net.Conn
	duplex         cyclist.Cyclist
	publicDH       PublicDH
	ephemeral      X25519KeyPair
	static         X25519KeyPair
	buf            []byte
	pos            int
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
	return c.clientHandshake()
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

type Config struct{}

func Client(conn net.Conn, config *Config) *Conn {
	return &Conn{
		underlyingConn: conn,
	}
}
