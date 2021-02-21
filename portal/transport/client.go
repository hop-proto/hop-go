package transport

import (
	"bytes"
	"io"
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
	m         sync.Mutex
	writeLock sync.Mutex
	readLock  sync.Mutex

	handshakeComplete atomicBool
	closed            atomicBool

	underlyingConn *net.UDPConn
	dialAddr       *net.UDPAddr

	hs *HandshakeState
	ss *SessionState

	readBuf bytes.Buffer
}

func (c *Client) lockUser() {
	c.m.Lock()
	c.writeLock.Lock()
	c.readLock.Lock()
}

func (c *Client) unlockUser() {
	c.m.Unlock()
	c.readLock.Unlock()
	c.writeLock.Unlock()
}

// Handshake performs the Portal handshake with the remote host. The connection
// must already be open. It is an error to call Handshake on a connection that
// has already performed the portal handshake.
func (c *Client) Handshake() error {
	if c.handshakeComplete.isSet() {
		return nil
	}

	c.lockUser()
	defer c.unlockUser()

	if c.handshakeComplete.isSet() {
		return nil
	}

	return c.clientHandshakeLocked()
}

func (c *Client) clientHandshakeLocked() error {
	c.hs = new(HandshakeState)
	c.hs.remoteAddr = c.dialAddr
	c.hs.duplex.InitializeEmpty()
	c.hs.ephemeral.Generate()

	// TODO(dadrian): This should actually be, well, static
	c.hs.static = new(X25519KeyPair)
	c.hs.static.Generate()

	c.hs.duplex.Absorb([]byte(ProtocolName))

	// TODO(dadrian): This should be allocated smaller
	buf := make([]byte, 65535)

	logrus.Debugf("client: public ephemeral: %x", c.hs.ephemeral.public)
	n, err := writeClientHello(c.hs, buf)
	if err != nil {
		return err
	}
	_, _, err = c.underlyingConn.WriteMsgUDP(buf[:n], nil, c.hs.remoteAddr)
	if err != nil {
		return err
	}
	// TODO(dadrian): Use ReadMsgUDP
	n, _, _, _, err = c.underlyingConn.ReadMsgUDP(buf, nil)
	if err != nil {
		return err
	}
	logrus.Debugf("client: recv %x", buf[:n])
	if n < 4 {
		return ErrInvalidMessage
	}
	n, err = readServerHello(c.hs, buf)
	if err != nil {
		return err
	}

	c.hs.RekeyFromSqueeze()

	// Client Ack
	n, err = c.hs.writeClientAck(buf, "david.test")
	if err != nil {
		return err
	}

	_, _, err = c.underlyingConn.WriteMsgUDP(buf[:n], nil, c.hs.remoteAddr)
	if err != nil {
		return err
	}

	// Server Auth
	msgLen, _, _, _, err := c.underlyingConn.ReadMsgUDP(buf, nil)
	if err != nil {
		return err
	}
	logrus.Debugf("clinet: sa msgLen: %d", msgLen)

	n, err = c.hs.readServerAuth(buf[:msgLen])
	if err != nil {
		return err
	}
	if n != msgLen {
		logrus.Debugf("got sa packet of %d, only read %d", msgLen, n)
		return ErrInvalidMessage
	}

	// Client Auth
	n, err = c.hs.writeClientAuth(buf)
	if err != nil {
		return err
	}
	_, _, err = c.underlyingConn.WriteMsgUDP(buf[:n], nil, c.hs.remoteAddr)
	if err != nil {
		logrus.Errorf("client: unable to send client auth: %s", err)
		return err
	}

	c.ss = new(SessionState)
	c.ss.sessionID = c.hs.sessionID
	c.ss.remoteAddr = *c.hs.remoteAddr
	c.hs.deriveFinalKeys(&c.ss.clientToServerKey, &c.ss.serverToClientKey)
	c.handshakeComplete.setTrue()
	c.closed.setFalse()
	c.hs = nil
	c.dialAddr = nil

	return nil
}

func (c *Client) writeTransport(plaintext []byte) error {
	err := c.ss.writePacket(c.underlyingConn, plaintext, &c.ss.clientToServerKey)
	if err != nil {
		return err
	}
	return nil
}

// Write implements net.Conn.
func (c *Client) Write(b []byte) (int, error) {
	if !c.handshakeComplete.isSet() {
		err := c.Handshake()
		if err != nil {
			return 0, err
		}
	}
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	if c.closed.isSet() {
		return 0, io.EOF
	}
	err := c.writeTransport(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close gracefully shutds down the connection. Repeated calls to close will error.
func (c *Client) Close() error {
	c.lockUser()
	defer c.unlockUser()

	if c.closed.isSet() {
		return io.EOF
	}

	c.closed.setTrue()
	c.handshakeComplete.setFalse()

	// TODO(dadrian): We should cache this error to return on repeated calls if
	// it fails.
	//
	// TODO(dadrian): Do we send a protocol close message?
	return c.underlyingConn.Close()
}

// Read implements net.Conn.
func (c *Client) Read(b []byte) (int, error) {
	// TODO(dadrian): Close the connection on bad reads?
	if !c.handshakeComplete.isSet() {
		err := c.Handshake()
		// TODO(dadrian): Cache handshake error?
		if err != nil {
			return 0, err
		}
	}
	// TODO(dadrian): #concurrency
	// TODO(dadrian): Avoid allocation?
	c.readLock.Lock()
	defer c.readLock.Unlock()
	if c.closed.isSet() {
		return 0, io.EOF
	}
	if c.readBuf.Len() > 0 {
		n, err := c.readBuf.Read(b)
		if c.readBuf.Len() == 0 {
			c.readBuf.Reset()
		}
		return n, err
	}
	ciphertext := make([]byte, 65535)
	msgLen, _, _, _, err := c.underlyingConn.ReadMsgUDP(ciphertext, nil)
	if err != nil {
		return 0, err
	}
	plaintextLen := PlaintextLen(msgLen)
	if plaintextLen < 0 {
		return 0, ErrInvalidMessage
	}
	// TODO(dadrian): If this implements io.Reader, we can probably avoid a
	// copy.
	// TODO(dadrian): Avoid an allocation
	plaintext := make([]byte, plaintextLen)
	c.ss.readPacket(plaintext, ciphertext[:msgLen], &c.ss.serverToClientKey)
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
func (c *Client) LocalAddr() net.Addr {
	c.lockUser()
	defer c.unlockUser()
	return c.underlyingConn.LocalAddr()
}

// RemoteAddr returns the underlying remote UDP address.
func (c *Client) RemoteAddr() net.Addr {
	c.lockUser()
	defer c.unlockUser()
	return c.underlyingConn.RemoteAddr()
}

// SetDeadline implements net.Conn.
func (c *Client) SetDeadline(t time.Time) error {
	c.lockUser()
	defer c.unlockUser()
	return c.underlyingConn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (c *Client) SetReadDeadline(t time.Time) error {
	c.lockUser()
	defer c.unlockUser()
	return c.underlyingConn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.
func (c *Client) SetWriteDeadline(t time.Time) error {
	c.lockUser()
	defer c.unlockUser()
	return c.underlyingConn.SetWriteDeadline(t)
}

// NewClient returns a Client configured as specified, using the underlying UDP
// connection. The Client has not yet completed a handshake.
func NewClient(conn *net.UDPConn, server *net.UDPAddr, config *Config) *Client {
	c := &Client{
		underlyingConn: conn,
		dialAddr:       server,
	}
	return c
}
