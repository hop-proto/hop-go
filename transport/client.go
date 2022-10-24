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

// Client implements net.Conn
//
// TODO(dadrian): Further document
type Client struct {
	m         sync.Mutex
	writeLock sync.Mutex
	readLock  sync.Mutex

	//+checklocks:m
	state connState

	wg sync.WaitGroup

	underlyingConn UDPLike

	// TODO(hosono) I don't think the dialAddr needs the locks, but it's only used when locked
	// +checklocks:m
	// +checklocks:readLock
	// +checklocks:writeLock
	dialAddr *net.UDPAddr

	// +checklocks:m
	// +checklocks:readLock
	// +checklocks:writeLock
	hs *HandshakeState

	ss *SessionState

	// +checklocks:readLock
	readBuf bytes.Buffer

	ciphertext []byte
	plaintext  []byte

	recv *common.DeadlineChan[[]byte]

	config ClientConfig
}

// +checklocksacquire:c.m
// +checklocksacquire:c.writeLock
// +checklocksacquire:c.readLock
func (c *Client) lockUser() {
	c.m.Lock()
	c.writeLock.Lock()
	c.readLock.Lock()
}

// +checklocksrelease:c.m
// +checklocksrelease:c.readLock
// +checklocksrelease:c.writeLock
func (c *Client) unlockUser() {
	c.readLock.Unlock()
	c.writeLock.Unlock()
	c.m.Unlock()
}

// IsClosed returns true if Close() has been called
func (c *Client) IsClosed() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.state == closed
}

// handshake complete returns true if the client has finished its handshake with the server
func (c *Client) handshakeComplete() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.state != finishingHandshake
}

// Handshake performs the Portal handshake with the remote host. The connection
// must already be open. It is an error to call Handshake on a connection that
// has already performed the portal handshake.
func (c *Client) Handshake() error {
	logrus.Info("Initiating Handshake")

	c.lockUser()
	defer c.unlockUser()

	if c.state != finishingHandshake {
		return nil
	}
	logrus.Debug("Handshake not complete. Completing handshake...")

	// TODO(dadrian): Cache any handshake errors

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
	c.setHSDeadline()

	c.ss = new(SessionState)
	c.ss.sessionID = c.hs.sessionID
	c.ss.remoteAddr = c.hs.remoteAddr
	c.hs.deriveFinalKeys(&c.ss.clientToServerKey, &c.ss.serverToClientKey)
	c.state = established
	c.hs = nil
	c.dialAddr = nil

	// Set deadline of 0 to make the connection not timeout
	// Data timeouts are handled by the Tube Muxer
	c.underlyingConn.SetReadDeadline(time.Time{})

	c.wg.Add(1)
	go c.listen()

	logrus.Info("Handshake Complete")
	return nil
}

func (c *Client) writeTransport(plaintext []byte) error {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	return c.ss.writePacket(c.underlyingConn, MessageTypeTransport, plaintext, &c.ss.clientToServerKey)
}

func (c *Client) writeControl(msg ControlMessage) error {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	plaintext := []byte{byte(msg)}
	return c.ss.writePacket(c.underlyingConn, MessageTypeControl, plaintext, &c.ss.clientToServerKey)
}

// Write implements net.Conn.
func (c *Client) Write(b []byte) (int, error) {
	if !c.handshakeComplete() {
		err := c.Handshake()
		if err != nil {
			return 0, err
		}
	}

	if c.IsClosed() {
		return 0, io.EOF
	}

	err := c.WriteMsg(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// WriteMsg implements MsgConn. It send a single packet.
func (c *Client) WriteMsg(b []byte) error {
	if !c.handshakeComplete() {
		err := c.Handshake()
		if err != nil {
			return err
		}
	}

	if c.IsClosed() {
		return io.EOF
	}

	err := c.writeTransport(b)
	if err != nil {
		return err
	}
	return nil

}

// Close immediately tears down the connection.
// Future operations on non-buffered data will return io.EOF
func (c *Client) Close() error {
	c.m.Lock()
	defer c.m.Unlock()

	if c.state == closed {
		return io.EOF
	}

	logrus.Debug("client: closing")

	c.writeControl(ControlMessageClose)

	c.recv.Close()
	err := c.underlyingConn.Close()

	// Wait for c.listen() to finish
	c.wg.Wait()

	c.state = closed

	return err
}

func (c *Client) listen() {
	defer c.wg.Done()
	for {
		n, mt, err := c.readMsg()

		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				logrus.Errorf("client: %s", err)
				go c.Close()
			}
			break
		}

		switch mt {
		case MessageTypeTransport:
			select {
			case c.recv.C <- append([]byte(nil), c.plaintext[:n]...):
				break
			default:
				logrus.Warn("client: recv queue full. dropping message")
			}
		case MessageTypeControl:
			if n != 1 {
				logrus.Errorf("client: malformed control message: %s", c.plaintext[:n])
				go c.Close()
			}
			msg := ControlMessage(c.plaintext[0])
			err := c.handleControlMsg(msg)
			if err != nil {
				go c.Close()
			}
		default:
			logrus.Errorf("client: unexpected message type %x", mt)
			go c.Close()
		}
	}
}

// handleControlMsg must only be called on authenticated packets after the handshake is complete.
// Due to the spoofable nature of UDP, control messages can be injected by third parties.
// both on the connection patch an off the connection path
func (c *Client) handleControlMsg(msg ControlMessage) (err error) {
	switch msg {
	case ControlMessageClose:
		logrus.Debug("client: got close message")
		c.recv.Close()
		return

	default:
		logrus.Errorf("client: invalid control message: %x", msg)
		go c.Close()
		return ErrInvalidMessage
	}
}

// readMsg reads one packet from the underlying connection, and writes it into c.plaintext
// It returns the number of bytes written into c.plaintext and any errors
// readMsg performs minimal error checking and should only be called when the
// connection is open and the handshake is complete.
// It uses both c.ciphertext and c.plaintext as scratch space
func (c *Client) readMsg() (int, MessageType, error) {
	msgLen, _, _, _, err := c.underlyingConn.ReadMsgUDP(c.ciphertext, nil)
	if err != nil {
		return 0, 0, err
	}

	plaintextLen := PlaintextLen(msgLen)
	if plaintextLen < 0 {
		return 0, 0, ErrInvalidMessage
	}

	n, mt, err := c.ss.readPacket(c.plaintext, c.ciphertext[:msgLen], &c.ss.serverToClientKey)
	if err != nil {
		return n, 0, err
	}

	// TODO(hosono) can this error actually happen?
	if n != plaintextLen {
		return n, 0, ErrInvalidMessage
	}

	return n, mt, nil
}

// ReadMsg reads a single message. If b is too short to hold the message, it is
// buffered and ErrBufOverflow is returned.
func (c *Client) ReadMsg(b []byte) (n int, err error) {
	// This ensures that errors that wrap errTransportOnly don't bubble up to the user
	defer func() {
		if errors.Is(err, errTransportOnly) {
			err = nil
		}
	}()

	if !c.handshakeComplete() {
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

	// This will cause an EOF error if the connection is closed
	plaintext, err := c.recv.Recv()
	if err != nil {
		return 0, err
	}

	// If the input is long enough, just copy into it
	if len(b) >= len(plaintext) {
		n = copy(b, plaintext)
		return n, nil
	}

	// Input was too short, buffer this message and return ErrBufOverflow
	_, err = c.readBuf.Write(plaintext)
	return 0, ErrBufOverflow
}

// Read implements net.Conn.
func (c *Client) Read(b []byte) (n int, err error) {
	// This ensures that errors that wrap errTransportOnly don't bubble up to the user
	defer func() {
		if errors.Is(err, errTransportOnly) {
			err = nil
		}
	}()

	if !c.handshakeComplete() {
		err := c.Handshake()
		// TODO(dadrian): Cache handshake error?
		if err != nil {
			return 0, err
		}
	}

	c.readLock.Lock()
	defer c.readLock.Unlock()

	if c.readBuf.Len() > 0 {
		n, err := c.readBuf.Read(b)
		if c.readBuf.Len() == 0 {
			c.readBuf.Reset()
		}
		return n, err
	}

	// This will cause an EOF error if the connection is closed
	plaintext, err := c.recv.Recv()
	if err != nil {
		return 0, err
	}

	n = copy(b, plaintext)
	if n == len(plaintext) {
		return n, nil
	}

	// Buffer leftovers
	_, err = c.readBuf.Write(plaintext[n:])
	return n, err
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
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline implements net.Conn.
func (c *Client) SetReadDeadline(t time.Time) error {
	return c.recv.SetDeadline(t)
}

// SetWriteDeadline implements net.Conn.
func (c *Client) SetWriteDeadline(t time.Time) error {
	return c.underlyingConn.SetWriteDeadline(t)
}

// NewClient returns a Client configured as specified, using the underlying UDP
// connection. The Client has not yet completed a handshake.
func NewClient(conn UDPLike, server *net.UDPAddr, config ClientConfig) *Client {
	c := &Client{
		underlyingConn: conn,
		dialAddr:       server,
		config:         config,
		ciphertext:     make([]byte, 65535),
		plaintext:      make([]byte, PlaintextLen(65535)),
		recv:           common.NewDeadlineChan[[]byte](config.maxBufferedPackets()),
	}
	return c
}
