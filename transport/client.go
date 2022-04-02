package transport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

//UDPLike interface standardizes Reliable channels and UDPConn.
//Reliable channels implement this interface so they can be used as the underlying conn for Clients
type UDPLike interface {
	net.Conn
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
}

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

	underlyingConn UDPLike
	dialAddr       *net.UDPAddr

	hs *HandshakeState
	ss *SessionState

	readBuf bytes.Buffer

	config ClientConfig
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
	logrus.Info("Initiating Handshake")
	if c.handshakeComplete.isSet() {
		return nil
	}
	logrus.Debug("Handshake not complete. Locking user...")
	c.lockUser()
	defer c.unlockUser()

	// TODO(dadrian): Cache any handshake errors

	if c.handshakeComplete.isSet() {
		return nil
	}
	logrus.Debug("got lock and checked again. Completeting handshake...")
	return c.clientHandshakeLocked()
}

func (c *Client) prepareCertificates() (leaf, intermediate []byte, err error) {
	if c.config.Exchanger == nil {
		return nil, nil, errors.New("ClientConfig.Exchanger must be non-nil, you probably want to provide a keys.X25519KeyPair")
	}

	if c.config.Leaf == nil {
		return nil, nil, errors.New("ClientConfig.Leaf must be non-nil when ClientConfig.UseCertificate is true")
	}
	if leaf, err = c.config.Leaf.Marshal(); err != nil {
		return nil, nil, fmt.Errorf("unable to serialize provided client leaf certificate: %w", err)
	}
	if c.config.Intermediate != nil {
		intermediate, err = c.config.Intermediate.Marshal()
	}
	return
}

func (c *Client) clientHandshakeLocked() error {
	c.hs = new(HandshakeState)
	c.hs.remoteAddr = c.dialAddr
	c.hs.duplex.InitializeEmpty()
	c.hs.ephemeral.Generate()

	var err error
	c.hs.leaf, c.hs.intermediate, err = c.prepareCertificates()
	if err != nil {
		return err
	}
	c.hs.static = c.config.Exchanger
	c.hs.certVerify = &c.config.Verify
	c.hs.duplex.Absorb([]byte(ProtocolName))

	// TODO(dadrian): This should be allocated smaller
	buf := make([]byte, 65535)

	logrus.Debugf("client: public ephemeral: %x", c.hs.ephemeral.Public)
	n, err := writeClientHello(c.hs, buf)
	if err != nil {
		return err
	}
	_, _, err = c.underlyingConn.WriteMsgUDP(buf[:n], nil, c.hs.remoteAddr)
	if err != nil {
		return err
	}

	n, _, _, _, err = c.underlyingConn.ReadMsgUDP(buf, nil)
	if err != nil {
		return err
	}
	logrus.Debugf("client: recv %x", buf[:n])
	if n < 4 {
		return ErrInvalidMessage
	}
	shn, err := readServerHello(c.hs, buf)
	if err != nil {
		return err
	}
	if shn != n {
		return fmt.Errorf("server hello too short. recevied %d bytes, SH only %d", n, shn)
	}

	c.hs.RekeyFromSqueeze()

	// Client Ack
	n, err = c.hs.writeClientAck(buf)
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
	err := c.WriteMsg(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// WriteMsg implements MsgConn. It send a single packet.
func (c *Client) WriteMsg(b []byte) error {
	if !c.handshakeComplete.isSet() {
		err := c.Handshake()
		if err != nil {
			return err
		}
	}
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	if c.closed.isSet() {
		return io.EOF
	}
	err := c.writeTransport(b)
	if err != nil {
		return err
	}
	return nil

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

// ReadMsg reads a single message. If b is too short to hold the message, it is
// buffered and ErrBufOverflow is returned.
func (c *Client) ReadMsg(b []byte) (int, error) {
	// TODO(dadrian): Close the connection on bad reads / certain unrecoverable
	// errors.
	if !c.handshakeComplete.isSet() {
		err := c.Handshake()
		if err != nil {
			return 0, err
		}
	}

	c.readLock.Lock()
	defer c.readLock.Unlock()

	if c.readBuf.Len() > 0 {
		if len(b) < c.readBuf.Len() {
			return 0, ErrBufOverflow
		}
		n, err := c.readBuf.Read(b)
		c.readBuf.Reset()
		return n, err
	}

	if c.closed.isSet() {
		return 0, io.EOF
	}

	// TODO(dadrian): Avoid allocation
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
	n, err := c.ss.readPacket(plaintext, ciphertext[:msgLen], &c.ss.serverToClientKey)
	if err != nil {
		return 0, err
	}
	if n != plaintextLen {
		return 0, ErrInvalidMessage
	}

	// If the input is long enough, just copy into it
	if len(b) >= plaintextLen {
		copy(b, plaintext[:n])
		return n, nil
	}

	// Input was too short, buffer this message and return ErrBufOverflow
	_, err = c.readBuf.Write(plaintext[n:])
	if err != nil {
		return 0, err
	}
	return 0, ErrBufOverflow
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
func NewClient(conn UDPLike, server *net.UDPAddr, config ClientConfig) *Client {
	c := &Client{
		underlyingConn: conn,
		dialAddr:       server,
		config:         config,
	}
	return c
}
