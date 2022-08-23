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

const (
	initiated uint32 = iota
	closeStart
	closed
)

type message struct {
	msgType MessageType
	data    []byte
}

// Handle implements net.Conn and MsgConn for connections accepted by a Server.
type Handle struct { // nolint:maligned // unclear if 120-byte struct is better than 128
	readLock  sync.Mutex
	writeLock sync.Mutex

	sendWg sync.WaitGroup

	recv *common.DeadlineChan[[]byte]  // incoming transport messages
	send *common.DeadlineChan[message] // outgoing messages

	state atomic.Uint32
	//closed atomic.Bool

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
	return c.state.Load() == closed
}

// ReadMsg implements the MsgReader interface. If b is too short to hold the
// message, it returns ErrBufOverflow.
func (c *Handle) ReadMsg(b []byte) (int, error) {
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

	if c.state.Load() != initiated {
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
	if c.state.Load() != initiated {
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
	if c.state.Load() == closed {
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
			logrus.Errorf("handle: resetting connection. unable to write packet: %s", err)
			go c.Reset()
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
		c.Reset()
		return ErrInvalidMessage
	}

	ctrlMsg := ControlMessage(msg[0])
	switch ctrlMsg {
	case ControlMessageClose:
		c.recv.Close()
		return nil
	case ControlMessageReset:
		logrus.Errorf("server: connection reset by remote peer")
		c.server.m.Lock()
		defer c.server.m.Unlock()
		c.shutdown(nil)
		return nil
	default:
		c.Reset()
		logrus.Error("server: unexpected control message ", msg)
		return ErrInvalidMessage
	}
}

// Start starts the goroutines that handle messages
func (c *Handle) Start() {
	c.sendWg.Add(1)
	go c.sender()
}

// Reset closes the connection without waiting for graceful shutdown
func (c *Handle) Reset() error {
	c.server.m.Lock()
	defer c.server.m.Unlock()
	msg := ControlMessageReset
	return c.shutdown(&msg)
}

// Close closes the connection. Future operations on non-buffered data will
// return io.EOF.
func (c *Handle) Close() error {
	c.server.m.Lock()
	defer c.server.m.Unlock()
	msg := ControlMessageClose
	return c.shutdown(&msg)
}

// Note that the lock here refers to the server's lock
// +checklocks:c.server.m
func (c *Handle) shutdown(msg *ControlMessage) error {
	if c.state.Load() == closed {
		return io.EOF
	}

	if msg != nil {
		c.WriteControl(*msg)
	}

	c.state.Store(closed)

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
