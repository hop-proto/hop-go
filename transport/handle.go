package transport

import (
	"bytes"
	"io"
	"net"
	"sync"
	"time"
)

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
	writeWg sync.WaitGroup

	readTimeout  atomicTimeout
	writeTimeout atomicTimeout

	sessionID SessionID

	//used by server to determine:
	//1.) if an authgrant was used for the session and
	//2.) to know which principal session to contact if the user wants to hop further
	//3.) (potentially) verify that only the allowed command is executed?
	AG        AuthGrant
	principal atomicBool //if true then no AG, if false then yes AG

	recv chan []byte
	send chan []byte

	closed atomicBool

	buf bytes.Buffer
}

var _ MsgReader = &Handle{}
var _ MsgWriter = &Handle{}
var _ MsgConn = &Handle{}

var _ net.Conn = &Handle{}

//GetPrincipalSession returns the Handle to the principal if this session is not it's own principal
func (c *Handle) GetPrincipalSession() (*Handle, bool) {
	if !c.principal.isSet() {
		c.readLock.Lock()
		defer c.readLock.Unlock()
		return c.AG.PrincipalSession, true
	}
	return nil, false
}

//IsClosed returns closed member variable value
func (c *Handle) IsClosed() bool {
	return c.closed.isSet()
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
	var msg []byte
	select {
	case msg = <-c.recv:
		break
	default:
		if c.closed.isSet() {
			return 0, io.EOF
		}
	}

	// Wait for a message until timeout
	if msg == nil {
		timer := time.NewTimer(c.readTimeout.get())
		select {
		case msg = <-c.recv:
			if !timer.Stop() {
				<-timer.C
			}
			break
		case <-timer.C:
			return 0, ErrTimeout
		}
	}

	// If the input is long enough, just copy into it
	if len(b) >= len(msg) {
		copy(b, msg)
		return len(msg), nil
	}

	// Input was too short, buffer this message and return ErrBufOverflow
	_, err := c.buf.Write(msg)
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

	// There must not be buffered data, fetch a message off the channel
	var msg []byte

	// Check and see if there are pending messages. This causes the queue to get
	// drained even if the connection is closed.
	select {
	case msg = <-c.recv:
		break
	default:
		if c.closed.isSet() {
			return 0, io.EOF
		}
	}

	// Wait for a message until timeout
	if msg == nil {
		timer := time.NewTimer(c.readTimeout.get())
		select {
		case msg = <-c.recv:
			if !timer.Stop() {
				<-timer.C
			}
			break
		case <-timer.C:
			return 0, ErrTimeout
		}
	}

	// Copy as much data as possible into the output data
	n := copy(b, msg)
	if n == len(msg) {
		return n, nil
	}
	// If there was leftover data, buffer it
	_, err := c.buf.Write(msg[n:])
	return n, err
}

// WriteMsg writes b as a single packet. If b is too long, WriteMsg returns
// ErrBufOverlow.
func (c *Handle) WriteMsg(b []byte) error {
	if len(b) > MaxPlaintextSize {
		return ErrBufOverflow
	}
	if c.closed.isSet() {
		return io.EOF
	}
	select {
	case c.send <- b:
		return nil
	default:
		if c.closed.isSet() {
			return io.EOF
		}
	}

	timer := time.NewTimer(c.writeTimeout.get())
	select {
	case c.send <- b:
		if !timer.Stop() {
			<-timer.C
		}
		return nil
	case <-timer.C:
		if c.closed.isSet() {
			return io.EOF
		}
		return ErrTimeout
	}
}

// Write implements io.Writer. It will split b into segments of length
// MaxPlaintextLength and send them using WriteMsg. Each call to WriteMsg is
// subject to the timeout.
func (c *Handle) Write(b []byte) (int, error) {
	if c.closed.isSet() {
		return 0, io.EOF
	}
	if len(b) <= MaxPlaintextSize {
		return len(b), c.WriteMsg(b)
	}
	total := 0
	for i := MaxPlaintextSize; i < len(b); i += MaxPlaintextSize {
		end := i + MaxPlaintextSize
		if end > len(b) {
			end = len(b)
		}
		err := c.WriteMsg(b[i:end])
		if err != nil {
			return total, err
		}
		total += end - i
	}
	return total, nil
}

func (c *Handle) close() {
	// TODO(dadrian): Implement
	// Remove the reference to the session, so it can be cleaned up
	// Close all the channels
	// Set the closed state
}

// Close closes the connection. Future operations on non-buffered data will
// return io.EOF.
//
// TODO(dadrian): Implement
func (c *Handle) Close() error {
	c.m.Lock()
	defer c.m.Unlock()

	return nil
}

// LocalAddr implements net.Conn.
//
// TODO(dadrian): Implement
func (c *Handle) LocalAddr() net.Addr {
	panic("unimplemented")
}

// RemoteAddr implements net.Conn.
//
// TODO(dadrian): Implement
func (c *Handle) RemoteAddr() net.Addr {
	panic("unimplemented")
}

// SetDeadline sets a deadline at which future operations will stop. It *might*
// not affect in-progress operations. It is implemented as a timeout, not a
// deadline.
//
// TODO(dadrian): Implement as a deadline.
func (c *Handle) SetDeadline(t time.Time) error {
	if c.closed.isSet() {
		return io.EOF
	}
	now := time.Now()
	var timeout time.Duration
	if t.After(now) {
		timeout = t.Sub(now)
	}
	c.readTimeout.set(timeout)
	c.writeTimeout.set(timeout)
	return nil
}

// SetReadDeadline sets a deadline at which future read operations will stop. It
// *might* not affect in-progress operations. It is implemented as a timeout,
// not a deadline.
//
// TODO(dadrian): Implement as a deadline.
func (c *Handle) SetReadDeadline(t time.Time) error {
	if c.closed.isSet() {
		return io.EOF
	}
	now := time.Now()
	var timeout time.Duration
	if t.After(now) {
		timeout = t.Sub(now)
	}
	c.readTimeout.set(timeout)
	return nil
}

// SetWriteDeadline sets a deadline at which future read operations will stop. It
// *might* not affect in-progress operations. It is implemented as a timeout,
// not a deadline.
//
// TODO(dadrian): Implement as a deadline.
func (c *Handle) SetWriteDeadline(t time.Time) error {
	if c.closed.isSet() {
		return io.EOF
	}
	now := time.Now()
	var timeout time.Duration
	if t.After(now) {
		timeout = t.Sub(now)
	}
	c.writeTimeout.set(timeout)
	return nil
}
