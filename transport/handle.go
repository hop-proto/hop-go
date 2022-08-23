package transport

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
)

type message struct {
	msgType MessageType
	data    []byte
}

// Handle implements net.Conn and MsgConn for connections accepted by a Server.
type Handle struct { // nolint:maligned // unclear if 120-byte struct is better than 128

	// TODO(dadrian): Not all of these are used, but also not all of the
	// functions are implemented yet. Remove unused variables when the
	// implementation settles down.
	m         sync.Mutex
	readLock  sync.Mutex
	writeLock sync.Mutex

	// TODO(dadrian): This might need to be a real condition variable. We don't
	// currently wait on it, but we Add/Done in the actual send write function.
	sendWg sync.WaitGroup

	recv *common.DeadlineChan[[]byte]  // incoming transport messages
	send *common.DeadlineChan[message] // outgoing messages

	closed atomic.Bool

	// +checklocks:readLock
	buf bytes.Buffer

	ss     *SessionState
	server *Server
}

var _ MsgReader = &Handle{}
var _ MsgWriter = &Handle{}
var _ MsgConn = &Handle{}

var _ net.Conn = &Handle{}

// IsClosed returns closed member variable value
func (c *Handle) IsClosed() bool {
	return c.closed.Load()
}

// ReadMsg implements the MsgReader interface. If b is too short to hold the
// message, it returns ErrBufOverflow.
func (c *Handle) ReadMsg(b []byte) (int, error) {
	// TODO(dadrian): Should we close the connection on read errors?
	// TODO(dadrian): This duplicates a lot of code from Read().
	c.readLock.Lock()
	defer c.readLock.Unlock()

	// If there's buffered data, return all of it.
	if c.buf.Len() > 0 {
		if len(b) < c.buf.Len() {
			return 0, ErrBufOverflow
		}
		n, err := c.buf.Read(b)
		c.buf.Reset()
		return n, err
	}

	// Check and see if there are pending messages. This causes the queue to get
	// drained even if the connection is closed.
	msg, err := c.recv.Recv()
	if err != nil {
		return 0, err
	}

	// If the input is long enough, just copy into it
	if len(b) >= len(msg) {
		copy(b, msg)
		return len(msg), nil
	}

	// Input was too short, buffer this message and return ErrBufOverflow
	_, err = c.buf.Write(msg)
	if err != nil {
		return 0, err
	}
	return 0, ErrBufOverflow

}

func (c *Handle) Read(b []byte) (int, error) {
	c.readLock.Lock()
	defer c.readLock.Unlock()

	// If there's buffered data, return all of it.
	if c.buf.Len() > 0 {
		n, err := c.buf.Read(b)
		if c.buf.Len() == 0 {
			c.buf.Reset()
		}
		return n, err
	}

	// Check and see if there are pending messages. This causes the queue to get
	// drained even if the connection is closed.
	msg, err := c.recv.Recv()
	if err != nil {
		return 0, err
	}

	// Copy as much data as possible into the output data
	n := copy(b, msg)
	if n == len(msg) {
		return n, nil
	}
	// If there was leftover data, buffer it
	_, err = c.buf.Write(msg[n:])
	return n, err
}

// WriteMsg writes b as a single packet. If b is too long, WriteMsg returns
// ErrBufOverlow.
func (c *Handle) WriteMsg(b []byte) error {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	if c.closed.Load() {
		return io.EOF
	}

	if len(b) > MaxPlaintextSize {
		return ErrBufOverflow
	}

	msg := message{
		data:    append([]byte{}, b...),
		msgType: MessageTypeTransport,
	}
	return c.send.Send(msg)
}

// Write implements io.Writer. It will split b into segments of length
// MaxPlaintextLength and send them using WriteMsg. Each call to WriteMsg is
// subject to the timeout.
func (c *Handle) Write(buf []byte) (int, error) {
	if c.closed.Load() {
		return 0, io.EOF
	}
	b := append([]byte{}, buf...)
	if len(b) <= MaxPlaintextSize {
		err := c.WriteMsg(b)
		if err != nil {
			return 0, err
		}
		return len(b), nil
	}
	total := 0
	for i := MaxPlaintextSize; i < len(b); i += MaxPlaintextSize {
		end := i + MaxPlaintextSize
		if end > len(b) {
			end = len(b)
		}
		err := c.WriteMsg((b[i:end]))
		if err != nil {
			return total, err
		}
		total += end - i
	}
	return total, nil
}

// WriteControl writes a control message to the remote host
func (c *Handle) WriteControl(msg ControlMessage) error {
	if c.closed.Load() {
		return io.EOF
	}
	toSend := message{
		data:    []byte{byte(msg)},
		msgType: MessageTypeControl,
	}
	return c.send.Send(toSend)
}

func (c *Handle) sender() {
	defer c.sendWg.Done()
	for {
		msg, err := c.send.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			} else if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			} else {
				logrus.Errorf("handle: error receiving from send channel: %s", err)
			}
		}

		err = c.ss.writePacket(c.server.udpConn, msg.msgType, msg.data, &c.ss.serverToClientKey)
		if err != nil {
			logrus.Errorf("handle: unable to write packet: %s", err)
			// TODO(dadrian): Should this affect connection state?
		}

		// end loop after sending control message
		if msg.msgType == MessageTypeControl && ControlMessage(msg.data[0]) == ControlMessageClose {
			break
		}
	}
}

func (c *Handle) handleControl(msg []byte) error {
	if len(msg) != 1 {
		logrus.Error("handle: invalid control message: ", msg)
		return ErrInvalidMessage
	}

	// TODO(hosono) handle other control messages
	ctrlMsg := ControlMessage(msg[0])
	switch ctrlMsg {
	case ControlMessageClose:
		c.recv.Close()
		return nil
	default:
		logrus.Error("server: unexpected control message ", msg)
		return ErrInvalidMessage
	}
}

// Start starts the goroutines that handle messages
func (c *Handle) Start() {
	c.sendWg.Add(1)
	go c.sender()
}

// Close closes the connection. Future operations on non-buffered data will
// return io.EOF.
func (c *Handle) Close() error {
	c.server.m.Lock()
	defer c.server.m.Unlock()
	return c.closeLocked()
}

// Note that the lock here refers to the server's lock
// +checklocks:c.server.m
func (c *Handle) closeLocked() error {
	if c.closed.Load() {
		return io.EOF
	}

	c.WriteControl(ControlMessageClose)
	c.closed.Store(true)

	c.recv.Close()
	c.send.Close()

	// Wait for the sending goroutines to exit
	c.sendWg.Wait()

	c.server.clearHandleLocked(c.ss.sessionID)

	return nil
}

// LocalAddr implements net.Conn.
func (c *Handle) LocalAddr() net.Addr {
	return c.server.udpConn.LocalAddr()
}

// RemoteAddr implements net.Conn.
func (c *Handle) RemoteAddr() net.Addr {
	return c.server.udpConn.RemoteAddr()
}

// SetDeadline sets a deadline at which future operations will stop.
// Pending operations will be canceled
func (c *Handle) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline sets a deadline at which future read operations will stop
// Pending reads will be canceled
func (c *Handle) SetReadDeadline(t time.Time) error {
	return c.recv.SetDeadline(t)
}

// SetWriteDeadline sets a deadline at which future read operations will stop
// Pending writes will be canceled
func (c *Handle) SetWriteDeadline(t time.Time) error {
	return c.send.SetDeadline(t)
}
