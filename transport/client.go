package transport

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
)

// UDPLike interface standardizes Reliable channels and UDPConn.
// Reliable channels implement this interface so they can be used as the underlying conn for Clients
type UDPLike interface {
	net.Conn
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
}

// Enforce ClientConn implements net.Conn
var _ net.Conn = &Client{}

const (
	clientStateCreated     = uint32(0)
	clientStateHandshaking = uint32(1)
	clientStateOpen        = uint32(2)
	clientStateClosing     = uint32(3)
	clientStateClosed      = uint32(4)
	clientStateError       = uint32(5)
)

// Client implements net.Conn.
//
// TODO(dadrian): Further document
type Client struct {
	wg    sync.WaitGroup
	state atomic.Uint32

	handshakeWg sync.WaitGroup

	underlyingConn UDPLike
	dialAddr       *net.UDPAddr

	// +checklocks:m
	err          error
	handshakeErr error
	hs           *HandshakeState

	ss *SessionState

	config ClientConfig

	closeWg sync.WaitGroup
}

// IsClosed returns true if Close() has finished.
func (c *Client) IsClosed() bool {
	return c.state.Load() == clientStateClosed
}

// Handshake performs the Portal handshake with the remote host. The connection
// must already be open. It is an error to call Handshake on a connection that
// has already performed the portal handshake.
func (c *Client) Handshake() error {
	state := c.state.Load()
	switch state {
	case clientStateHandshaking:
		// Wait for the handshake to finish, then return the cached error.
		c.handshakeWg.Wait()
		return c.handshakeErr
	case clientStateOpen:
		// If the client is open, it can't have had a handshake error.
		return nil
	case clientStateError:
		return c.err
	case clientStateClosing, clientStateClosed:
		if c.hs != nil {
			return nil
		}
		return io.EOF
	}

	// Only add to the semaphor if the first check indicates we might need to handshake.
	c.handshakeWg.Add(1)
	for !c.state.CompareAndSwap(clientStateCreated, clientStateHandshaking) {
		state := c.state.Load()
		switch state {
		case clientStateCreated:
			// Do nothing, try again
		case clientStateHandshaking:
			c.handshakeWg.Done()
			c.handshakeWg.Wait()
			return c.handshakeErr
		case clientStateOpen:
			c.handshakeWg.Done()
			return nil
		case clientStateError:
			return c.err
		case clientStateClosing, clientStateClosed:
			c.handshakeWg.Done()
			if c.hs != nil {
				return nil
			}
			return io.EOF
		}
	}
	defer c.handshakeWg.Done()
	logrus.Info("Handshake not complete. Completing handshake...")
	c.handshakeErr = c.clientHandshakeLocked()
	if c.handshakeErr != nil {
		c.hs = nil
		c.ss = nil
		c.err = c.handshakeErr
		c.state.Store(clientStateError)
	}
	return c.handshakeErr
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

// Set time after which connection will fail considering timeout and deadline
func (c *Client) setHSDeadline() {
	if !c.config.HSDeadline.IsZero() {
		c.underlyingConn.SetReadDeadline(c.config.HSDeadline)
	}

	if c.config.HSTimeout != 0 {
		if deadline := time.Now().Add(c.config.HSTimeout); c.config.HSDeadline.IsZero() || deadline.Before(c.config.HSDeadline) {
			c.underlyingConn.SetReadDeadline(deadline)
		}
	}
}

// +checklocks:c.m
// +checklocks:c.readLock
// +checklocks:c.writeLock
func (c *Client) clientHandshakeLocked() error {
	c.state.Store(clientStateHandshaking)
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

	// TODO(dadrian): This should be allocated smaller
	buf := make([]byte, 65535)

	logrus.Debugf("client: public ephemeral: %x", c.hs.ephemeral.Public)

	if c.config.ServerPublicKey != nil {
		logrus.Debug("---------- HIDDEN HANDSHAKE MODE -------------")

		err := c.clientHiddenHandshakeBuilder(buf)
		if err != nil {
			return err
		}
	} else {
		err := c.clientDiscoverableHandshakeBuilder(buf)
		if err != nil {
			return err
		}
	}
	c.setHSDeadline()

	c.ss = new(SessionState)
	c.ss.sessionID = c.hs.sessionID
	c.ss.remoteAddr = c.hs.remoteAddr
	if err := c.hs.deriveFinalKeys(&c.ss.clientToServerKey, &c.ss.serverToClientKey); err != nil {
		return err
	}
	c.ss.readKey = &c.ss.serverToClientKey
	c.ss.writeKey = &c.ss.clientToServerKey
	c.hs = nil
	c.dialAddr = nil

	// Set deadline of 0 to make the connection not timeout
	// Data timeouts are handled by the Tube Muxer
	//
	// TODO(dadrian)[2023-09-10]: This shouldn't happen here. The Dialer or
	// DialContext functions should take a timeout or something like that. Also
	// we should have a DialContext.
	c.underlyingConn.SetReadDeadline(time.Time{})
	c.ss.handle = newHandleForSession(c.underlyingConn, c.ss, c.config.Leaf, c.config.maxBufferedPackets())
	c.state.Store(clientStateOpen)
	c.wg.Add(1)
	go c.listen()

	return nil
}

func (c *Client) clientDiscoverableHandshakeBuilder(buf []byte) error {
	// Protocol ID for the regular handshake
	c.hs.duplex.Absorb([]byte(ProtocolName))

	n, err := writeClientHello(c.hs, buf)
	if err != nil {
		return err
	}
	_, _, err = c.underlyingConn.WriteMsgUDP(buf[:n], nil, c.hs.remoteAddr)
	if err != nil {
		return err
	}
	c.setHSDeadline()

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

	c.hs.RekeyFromSqueeze(ProtocolName)

	// Client Ack
	n, err = c.hs.writeClientAck(buf)
	if err != nil {
		return err
	}

	_, _, err = c.underlyingConn.WriteMsgUDP(buf[:n], nil, c.hs.remoteAddr)
	if err != nil {
		return err
	}
	c.setHSDeadline()

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
	return nil
}

func (c *Client) clientHiddenHandshakeBuilder(buf []byte) error {
	// Protocol ID for the hidden handshake
	c.hs.duplex.Absorb([]byte(HiddenProtocolName))

	c.hs.RekeyFromSqueeze(HiddenProtocolName)

	n, err := c.hs.writeClientRequestHidden(buf, c.config.ServerPublicKey)

	if err != nil {
		return err
	}
	_, _, err = c.underlyingConn.WriteMsgUDP(buf[:n], nil, c.hs.remoteAddr)
	if err != nil {
		logrus.Errorf("client: unable to make a hidden request: %s", err)
		return err
	}

	// Server Response hidden
	msgLen, _, _, _, err := c.underlyingConn.ReadMsgUDP(buf, nil)
	if err != nil {
		return err
	}
	logrus.Debugf("client: Server response hidden msgLen: %d", msgLen)

	n, err = c.hs.readServerResponseHidden(buf[:msgLen])
	if err != nil {
		return err
	}
	if n != msgLen {
		logrus.Debugf("client: Server response hidden packet of %d, only read %d", msgLen, n)
		return ErrInvalidMessage
	}

	c.hs.isHiddenHSCompleted = true

	return nil
}

func (c *Client) listen() {
	defer c.wg.Done()
	ciphertext := make([]byte, 65535)
	c.handshakeWg.Wait()
	for c.state.Load() == clientStateOpen {
		msgLen, _, _, addr, err := c.underlyingConn.ReadMsgUDP(ciphertext, nil)
		if err != nil {
			if c.state.Load() != clientStateOpen {
				continue
			}
			logrus.Errorf("client: error reading packet %s", err)
		}
		c.handleSessionMessage(addr, ciphertext[:msgLen])
	}
}

func (c *Client) handleSessionMessage(addr *net.UDPAddr, msg []byte) error {
	sessionID, err := PeekSession(msg)
	if err != nil {
		return err
	}
	if common.Debug {
		logrus.Tracef("client: transport/control message for session %x", sessionID)
	}

	c.ss.m.Lock()
	defer c.ss.m.Unlock()
	if sessionID != c.ss.sessionID {
		return ErrUnknownSession
	}

	// TODO(dadrian): Can we avoid this allocation?
	plaintext := make([]byte, PlaintextLen(len(msg)))
	_, mt, err := c.ss.readPacketLocked(plaintext, msg, c.ss.readKey)
	if err != nil {
		return err
	}
	if common.Debug {
		logrus.Tracef("client: session %x: plaintextLen: %d type: %x from: %s", c.ss.sessionID, len(plaintext), mt, addr)
	}

	switch mt {
	case MessageTypeTransport:
		select {
		case c.ss.handle.recv.C <- plaintext:
			break
		default:
			logrus.Warnf("session %x: recv queue full, dropping packet", sessionID)
		}
	case MessageTypeControl:
		if err := c.ss.handleControlLocked(plaintext); err != nil {
			return err
		}
	default:
		// Close the connection on an unknown message type
		c.ss.closeLocked()
		return ErrInvalidMessage
	}

	if !EqualUDPAddress(c.ss.remoteAddr, addr) {
		c.ss.remoteAddr = addr
	}
	return nil
}

// Write implements net.Conn.
func (c *Client) Write(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	return c.ss.handle.Write(b)
}

// WriteMsg implements MsgConn. It send a single frame.
func (c *Client) WriteMsg(b []byte) error {
	if err := c.Handshake(); err != nil {
		return err
	}
	return c.ss.handle.WriteMsg(b)
}

// ReadMsg reads a single message. If b is too short to hold the message, it is
// buffered and ErrBufOverflow is returned.
func (c *Client) ReadMsg(b []byte) (n int, err error) {
	switch c.state.Load() {
	case clientStateCreated, clientStateHandshaking:
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	case clientStateError:
		return 0, c.err
	}
	return c.ss.handle.ReadMsg(b)
}

// Read implements net.Conn.
func (c *Client) Read(b []byte) (n int, err error) {
	switch c.state.Load() {
	case clientStateCreated, clientStateHandshaking:
		if err := c.Handshake(); err != nil {
			return 0, err
		}
	case clientStateError:
		return 0, c.err
	}
	return c.ss.handle.Read(b)
}

// LocalAddr returns the underlying UDP address.
func (c *Client) LocalAddr() net.Addr {
	return c.underlyingConn.LocalAddr()
}

// RemoteAddr returns the underlying remote UDP address.
func (c *Client) RemoteAddr() net.Addr {
	return c.underlyingConn.RemoteAddr()
}

// SetDeadline implements net.Conn.
func (c *Client) SetDeadline(t time.Time) error {
	if c.state.Load() == clientStateOpen {
		return c.ss.handle.SetDeadline(t)
	}
	// TODO(dadrian)[2023-09-10]: What about the other cases?
	return nil
}

// SetReadDeadline implements net.Conn.
func (c *Client) SetReadDeadline(t time.Time) error {
	if c.state.Load() == clientStateOpen {
		return c.ss.handle.SetReadDeadline(t)
	}
	// TODO(dadrian)[2023-09-10]: What about the other cases?
	return nil
}

// SetWriteDeadline implements net.Conn.
func (c *Client) SetWriteDeadline(t time.Time) error {
	if c.state.Load() == clientStateOpen {
		return c.ss.handle.SetWriteDeadline(t)
	}
	// TODO(dadrian)[2023-09-10]: What about the other cases?
	return nil
}

// Close immediately tears down the connection.
// Future operations on non-buffered data will return io.EOF
func (c *Client) Close() error {
	c.closeWg.Add(1)
	for !c.state.CompareAndSwap(clientStateOpen, clientStateClosing) {
		cur := c.state.Load()
		switch cur {
		case clientStateCreated:
			if c.state.CompareAndSwap(clientStateCreated, clientStateClosed) {
				c.closeWg.Done()
				return nil
			}
		case clientStateHandshaking:
			c.handshakeWg.Wait()
		case clientStateClosing:
			c.closeWg.Done()
			c.closeWg.Wait()
			return nil
		case clientStateClosed:
			c.closeWg.Done()
			return nil
		case clientStateError:
			c.closeWg.Done()
			return c.err
		}
	}
	defer c.closeWg.Done()
	// TODO(dadrian)[2024-04-07]: Document why this is correct, or fix it.
	c.underlyingConn.SetReadDeadline(time.Now())

	c.wg.Wait()

	c.state.Store(clientStateClosed)
	c.ss.handle.Close()
	c.underlyingConn.Close()

	return nil
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
