package transport

import (
	"bytes"
	"io"
	"net"
	"sync"
	"time"

	"hop.computer/hop/certs"
	"hop.computer/hop/common"
)

// Handle implements net.Conn and MsgConn for connections accepted by a Server.
type Handle struct { // nolint:maligned // unclear if 120-byte struct is better than 128
	readLock sync.Mutex

	underlying UDPLike                      // outgoing socket-like
	recv       *common.DeadlineChan[[]byte] // incoming transport messages

	// +checklocks:readLock
	buf bytes.Buffer

	// Constant after initialization
	clientLeaf certs.Certificate
	ss         *SessionState
}

var _ MsgReader = &Handle{}
var _ MsgWriter = &Handle{}
var _ MsgConn = &Handle{}

var _ net.Conn = &Handle{}

func newHandleForSession(underlying UDPLike, ss *SessionState, packetBufLen int) *Handle {
	return &Handle{
		recv:       common.NewDeadlineChan[[]byte](packetBufLen),
		underlying: underlying,
		ss:         ss,
	}
}

// IsClosed returns true if the handle is closed or in the process of closing.
// Writes and reads to the handle return io.EOF if and only if IsClosed returns true
func (c *Handle) IsClosed() bool {
	c.ss.m.Lock()
	defer c.ss.m.Unlock()
	return c.ss.handleState == closed
}

// ReadMsg implements the MsgReader interface. If b is too short to hold the
// message, it returns ErrBufOverflow.
func (c *Handle) ReadMsg(b []byte) (int, error) {
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
	if len(b) > MaxPlaintextSize {
		return ErrBufOverflow
	}
	return c.send(MessageTypeTransport, b)
}

// Write implements io.Writer. It will split b into segments of length
// MaxPlaintextLength and send them using WriteMsg. Each call to WriteMsg is
// subject to the timeout.
func (c *Handle) Write(buf []byte) (int, error) {
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

// writeControl writes a control message to the remote host
// TODO(hosono) fix lint error
// nolint
func (c *Handle) writeControlLocked(msg ControlMessage) error {
	return c.ss.writePacketLocked(c.underlying, MessageTypeControl, []byte{byte(msg)}, c.ss.writeKey)
}

func (c *Handle) send(msgType MessageType, b []byte) error {
	c.ss.m.Lock()
	defer c.ss.m.Unlock()
	if c.ss.handleState == closed {
		return io.EOF
	}
	err := c.ss.writePacketLocked(c.underlying, msgType, b, c.ss.writeKey)
	if err != nil {
		// TODO(dadrian)[2023-09-08]: Is this necessary or correct?
		go c.Close()
	}
	return err
}

// Close closes the connection. Future operations on non-buffered data will return io.EOF.
func (c *Handle) Close() error {
	c.ss.m.Lock()
	defer c.ss.m.Unlock()

	c.recv.Close()

	return c.ss.closeLocked()
}

// FetchClientLeaf returns the certificate the client presented when setting up the connection
func (c *Handle) FetchClientLeaf() certs.Certificate {
	return c.clientLeaf
}

// LocalAddr implements net.Conn.
func (c *Handle) LocalAddr() net.Addr {
	return c.underlying.LocalAddr()
}

// RemoteAddr implements net.Conn.
func (c *Handle) RemoteAddr() net.Addr {
	return c.underlying.RemoteAddr()
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
func (c *Handle) SetWriteDeadline(_ time.Time) error {
	// There is no actual write deadline because sends go out immediately, subject to locking.
	//
	// TODO(dadrian)[2023-09-08]: Somehow limit lock wait time to write deadline.
	return nil
}
