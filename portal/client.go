package portal

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Enforce ClientConn implements net.Conn
var _ net.Conn = &Client{}

// Client implements net.Conn
//
// TODO(dadrian): Further document
type Client struct {
	m  sync.Mutex
	hs HandshakeState

	underlyingConn *net.UDPConn

	buf []byte
	pos int

	encBuf []byte

	macBuf       [MacLen]byte
	handshakeKey [KeyLen]byte

	es []byte
	se []byte

	sessionID  SessionID
	sessionKey [KeyLen]byte

	readBuf bytes.Buffer
}

// Handshake performs the Portal handshake with the remote host. The connection
// must already be open. It is an error to call Handshake on a connection that
// has already performed the portal handshake.
func (c *Client) Handshake() error {
	c.m.Lock()
	defer c.m.Unlock()
	c.buf = make([]byte, 1024*1024)
	c.encBuf = make([]byte, len(c.buf))
	c.pos = 0
	return c.clientHandshake()
}

func (c *Client) initializeKeyMaterial() {
	c.hs.duplex.InitializeEmpty()
	c.hs.ephemeral.Generate()

	// TODO(dadrian): This should actually be, well, static
	c.hs.static.Generate()

	c.hs.duplex.Absorb([]byte(ProtocolName))
}

func (c *Client) clientHandshake() error {
	c.initializeKeyMaterial()
	logrus.Debugf("client: public ephemeral: %x", c.hs.ephemeral.public)
	n, err := writeClientHello(&c.hs, c.buf)
	if err != nil {
		return err
	}
	n, err = c.underlyingConn.Write(c.buf[:n])
	if err != nil {
		return err
	}
	// TODO(dadrian): Use ReadMsgUDP
	n, err = c.underlyingConn.Read(c.buf)
	if err != nil {
		return err
	}
	logrus.Debugf("client: recv %x", c.buf[:n])
	if n < 4 {
		return ErrInvalidMessage
	}
	n, err = readServerHello(&c.hs, c.buf)
	if err != nil {
		return err
	}

	c.hs.RekeyFromSqueeze()

	n, err = c.hs.writeClientAck(c.buf, "david.test")
	if err != nil {
		return err
	}

	_, err = c.underlyingConn.Write(c.buf[:n])
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
	c.hs.duplex.Absorb(x[:HeaderLen])

	x = x[HeaderLen:]
	copy(c.sessionID[:], x[:SessionIDLen])
	c.hs.duplex.Absorb(x[:SessionIDLen])
	x = x[SessionIDLen:]
	if len(x) < encCertLen {
		logrus.Debug("client: no room for certs")
		return ErrBufUnderflow
	}
	leaf, intermediate, err := DecryptCertificates(&c.hs.duplex, x[:encCertLen])
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
	c.hs.duplex.Squeeze(c.macBuf[:])
	logrus.Debugf("client: sa tag: %x", c.macBuf)
	if !bytes.Equal(c.macBuf[:], x[:MacLen]) {
		logrus.Debug("client: sa tag mismatch")
	}
	x = x[MacLen:]
	c.es, err = c.hs.ephemeral.DH(leaf)
	if err != nil {
		logrus.Debug("client: couldn't do es")
		return err
	}
	logrus.Debugf("client: es %x", c.es)
	c.hs.duplex.Absorb(c.es)
	c.hs.duplex.Squeeze(c.macBuf[:])
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
	c.hs.duplex.Absorb(b[0:4])
	b = b[4:]
	c.pos += 4
	copy(b, c.sessionID[:])
	c.hs.duplex.Absorb(c.sessionID[:])
	b = b[SessionIDLen:]
	c.pos += SessionIDLen
	c.hs.duplex.Encrypt(b[:DHLen], c.hs.static.public[:])
	b = b[DHLen:]
	c.pos += DHLen
	c.hs.duplex.Squeeze(b[:MacLen]) // tag
	b = b[MacLen:]
	c.pos += MacLen
	c.se, err = c.hs.static.DH(c.hs.clientEphemeral[:])
	if err != nil {
		logrus.Errorf("client: unable to calc se: %s", err)
		return err
	}
	logrus.Debugf("client: se %x", c.se)
	c.hs.duplex.Absorb(c.se)
	c.hs.duplex.Squeeze(b[:MacLen]) // mac
	b = b[MacLen:]
	c.pos += MacLen
	n, err = c.underlyingConn.Write(c.buf[0:c.pos])
	if err != nil {
		logrus.Errorf("client: unable to send client auth: %s", err)
		return err
	}
	return nil
}

func (c *Client) writeTransport(plaintext []byte) (int, error) {
	buf := make([]byte, HeaderLen+SessionIDLen+CounterLen+len(plaintext)+MacLen)
	n := 0
	x := buf
	x[0] = MessageTypeTransport
	x[1] = 0
	x[2] = 0
	x[3] = 0
	x = x[4:]
	n += 4
	copy(x, c.sessionID[:])
	x = x[SessionIDLen:]
	n += SessionIDLen
	// TODO(dadrian): Tracks sequence numbers
	copy(x, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	x = x[CounterLen:]
	n += CounterLen
	// TODO(dadrian): Implement encryption
	copy(x, plaintext)
	x = x[len(plaintext):]
	n += len(plaintext)
	c.hs.duplex.Absorb(buf[0:n])
	c.hs.duplex.Squeeze(x[:MacLen])
	n += MacLen
	written, err := c.underlyingConn.Write(buf)
	if written != n {
		panic("fuck")
	}
	return len(plaintext), err
}

func (c *Client) readTransport(msg []byte) ([]byte, error) {
	if len(msg) < HeaderLen+SessionIDLen+CounterLen+MacLen {
		return nil, ErrInvalidMessage
	}
	x := msg
	if x[0] != MessageTypeTransport {
		return nil, ErrUnexpectedMessage
	}
	if x[1] != 0 || x[2] != 0 || x[3] != 0 {
		return nil, ErrInvalidMessage
	}
	x = x[HeaderLen:]
	var sessionID SessionID
	copy(sessionID[:], x[:SessionIDLen])
	if c.sessionID != sessionID {
		return nil, ErrUnknownSession
	}
	x = x[SessionIDLen:]
	counter := binary.LittleEndian.Uint64(x)
	x = x[CounterLen:]
	logrus.Debugf("client: handling transport message from %s with counter %d", c.RemoteAddr(), counter)
	dataLen := len(x) - MacLen
	// TODO(dadrian): Decryption
	// TODO(dadrian): Mac verification
	out := make([]byte, dataLen)
	copy(out, x[:dataLen])
	return out, nil
}

// Write implements net.Conn.
func (c *Client) Write(b []byte) (n int, err error) {
	// TODO(dadrian): #concurrency
	return c.writeTransport(b)
}

// Close gracefully shutds down the connection. Repeated calls to close will error.
func (c *Client) Close() error {
	// TODO(dadrian): #concurrency
	// TODO(dadrian): Do we send a protocol close message?
	return c.underlyingConn.Close()
}

// Read implements net.Conn.
func (c *Client) Read(b []byte) (int, error) {
	// TODO(dadrian): #concurrency
	// TODO(dadrian): Enforce handshake has happened
	// TODO(dadrian): Share code with server-side conn?
	// TODO(dadrian): Avoid allocation?
	if c.readBuf.Len() > 0 {
		n, err := c.readBuf.Read(b)
		if c.readBuf.Len() == 0 {
			c.readBuf.Reset()
		}
		return n, err
	}
	ciphertext := make([]byte, 65535)
	msgLen, err := c.underlyingConn.Read(ciphertext)
	if err != nil {
		return 0, err
	}
	plaintext, err := c.readTransport(ciphertext[:msgLen])
	if err != nil {
		return 0, err
	}
	n := copy(b, plaintext)
	if n == len(plaintext) {
		return n, nil
	}
	// Buffer leftovers
	// TODO(dadrian): Handle this error?
	_, err = c.readBuf.Write(plaintext[n:])
	return n, err
}

// LocalAddr returns the underlying UDP address.
//
// TODO(dadrian): Should this be a subspace address?
func (c *Client) LocalAddr() net.Addr {
	return c.underlyingConn.LocalAddr()
}

// RemoteAddr returns the underlying remote UDP address.
//
// TODO(dadrian): Should this be a subspace address?
func (c *Client) RemoteAddr() net.Addr {
	return c.underlyingConn.RemoteAddr()
}

// SetDeadline implements net.Conn.
func (c *Client) SetDeadline(t time.Time) error {
	return c.underlyingConn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (c *Client) SetReadDeadline(t time.Time) error {
	return c.underlyingConn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.
func (c *Client) SetWriteDeadline(t time.Time) error {
	return c.underlyingConn.SetWriteDeadline(t)
}

// NewClient returns a Client configured as specified, using the underlying UDP
// connection. The Client has not yet completed a handshake.
func NewClient(conn *net.UDPConn, config *Config) *Client {
	c := &Client{
		underlyingConn: conn,
	}
	return c
}
