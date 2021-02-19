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
	m         sync.Mutex
	writeLock sync.Mutex
	readLock  sync.Mutex

	hs *HandshakeState

	handshakeComplete atomicBool

	underlyingConn *net.UDPConn

	buf []byte

	readBuf bytes.Buffer
	rawRead bytes.Buffer

	sessionID         SessionID
	clientToServerKey [KeyLen]byte
	serverToClientKey [KeyLen]byte
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

	c.buf = make([]byte, 65535)
	return c.clientHandshakeLocked()
}

func (c *Client) clientHandshakeLocked() error {
	c.hs = new(HandshakeState)
	c.hs.duplex.InitializeEmpty()
	c.hs.ephemeral.Generate()

	// TODO(dadrian): This should actually be, well, static
	c.hs.static = new(X25519KeyPair)
	c.hs.static.Generate()

	c.hs.duplex.Absorb([]byte(ProtocolName))

	logrus.Debugf("client: public ephemeral: %x", c.hs.ephemeral.public)
	n, err := writeClientHello(c.hs, c.buf)
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
	n, err = readServerHello(c.hs, c.buf)
	if err != nil {
		return err
	}

	c.hs.RekeyFromSqueeze()

	// Client Ack
	n, err = c.hs.writeClientAck(c.buf, "david.test")
	if err != nil {
		return err
	}

	_, err = c.underlyingConn.Write(c.buf[:n])
	if err != nil {
		return err
	}

	// Server Auth
	msgLen, err := c.underlyingConn.Read(c.buf)
	if err != nil {
		return err
	}
	logrus.Debugf("clinet: sa msgLen: %d", msgLen)

	n, err = c.hs.readServerAuth(c.buf[:msgLen])
	if err != nil {
		return err
	}
	if n != msgLen {
		logrus.Debugf("got sa packet of %d, only read %d", msgLen, n)
		return ErrInvalidMessage
	}

	// Client Auth
	n, err = c.hs.writeClientAuth(c.buf)
	if err != nil {
		return err
	}
	_, err = c.underlyingConn.Write(c.buf[:n])
	if err != nil {
		logrus.Errorf("client: unable to send client auth: %s", err)
		return err
	}

	c.hs.deriveFinalKeys(&c.clientToServerKey, &c.serverToClientKey)
	c.sessionID = c.hs.sessionID
	c.handshakeComplete.setTrue()
	c.hs = nil

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
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
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
	// TODO(dadrian): If this implements io.Reader, we can probably avoid a
	// copy.
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
func NewClient(conn *net.UDPConn, config *Config) *Client {
	c := &Client{
		underlyingConn: conn,
	}
	return c
}
