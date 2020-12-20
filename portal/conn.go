package portal

import (
	"bytes"
	"net"
	"sync"
	"time"
)

var _ net.Conn = &Conn{}

type Conn struct {
	m sync.Mutex

	closed bool

	// TODO(dadrian): Figure out how to make this not need a reference back
	s         *Server
	sessionID SessionID

	in  chan []byte
	out chan []byte

	signal chan int

	buf bytes.Buffer
}

func (c *Conn) Close() error {
	// TODO(dadrian)
	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	c.m.Lock()
	defer c.m.Unlock()
	// If there's buffered data, return all of it.
	if c.buf.Len() > 0 {
		n, err := c.buf.Read(b)
		if c.buf.Len() == 0 {
			c.buf.Reset()
		}
		return n, err
	}
	// There must not be buffered data, fetch a message off the channel
	// TODO(dadrian): Handle timeouts
	msg := <-c.in
	n := copy(b, msg)
	if n == len(msg) {
		return n, nil
	}
	// If there was leftover data, buffer it
	_, err := c.buf.Write(msg[n:])
	return n, err
}

// Write implements net.Conn
// TODO(dadrian): Handle timeouts and deadlines
func (c *Conn) Write(b []byte) (int, error) {
	c.m.Lock()
	defer c.m.Unlock()
	err := c.s.writeToSession(b, c.sessionID)
	if err != nil {
		return 0, nil
	}
	return len(b), nil
}

// LocalAddr implements net.Conn.
func (c *Conn) LocalAddr() net.Addr {
	c.m.Lock()
	defer c.m.Unlock()
	return c.s.LocalAddr()
}

// RemoteAddr implements net.Conn.
func (c *Conn) RemoteAddr() net.Addr {
	c.m.Lock()
	defer c.m.Unlock()
	return c.s.RemoteAddrFor(c.sessionID)
}

func (c *Conn) SetReadDeadline(deadline time.Time) error {
	return nil
}

func (c *Conn) SetWriteDeadline(deadline time.Time) error {
	return nil
}

func (c *Conn) SetDeadline(deadline time.Time) error {
	return nil
}
