package transport

import (
	"bytes"
	"io"
	"sync"
	"time"
)

type RWHandle struct {
	m        sync.Mutex
	readLock sync.Mutex

	timeout time.Duration

	sessionID SessionID
	recv      chan []byte
	send      chan []byte

	closed atomicBool

	buf bytes.Buffer
}

func (c *RWHandle) lockUser() {
	c.m.Lock()
	c.readLock.Lock()
}

func (c *RWHandle) unlockUser() {
	c.readLock.Unlock()
	c.m.Unlock()
}

func (c *RWHandle) Read(b []byte) (int, error) {
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
		timer := time.NewTimer(c.timeout)
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

func (c *RWHandle) Write(b []byte) (int, error) {
	select {
	case c.send <- b:
		return len(b), nil
	default:
		return 0, ErrWouldBlock
	}
}

func (c *RWHandle) close() {
	// TODO(dadrian): Implement
	// Remove the reference to the session, so it can be cleaned up
	// Close all the channels
	// Set the closed state
}

func (c *RWHandle) Close() error {
	c.m.Lock()
	defer c.m.Unlock()

	return nil
}
