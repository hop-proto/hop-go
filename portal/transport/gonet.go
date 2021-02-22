package transport

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Client directly implements net.Conn
var _ net.Conn = &Client{}

// ErrUDPOnly is returned when non-UDP connections are attempted or used.
var ErrUDPOnly = errors.New("portal requires UDP transport")

// Dial matches the interface of net.Dial
func Dial(network, address string, config *ClientConfig) (*Client, error) {
	if network != "udp" && network != "subspace" {
		return nil, ErrUDPOnly
	}

	// Figure out what address we would use to dial
	throwaway, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	localAddr := throwaway.LocalAddr()
	remoteAddr := throwaway.RemoteAddr()
	throwaway.Close()

	// Recreate as a non-connected socket
	inner, err := net.ListenUDP("udp", localAddr.(*net.UDPAddr))
	if err != nil {
		return nil, err
	}
	return NewClient(inner, remoteAddr.(*net.UDPAddr), config), nil
}

type Conn struct {
	m         sync.Mutex
	readLock  sync.Mutex
	writeLock sync.Mutex

	closed atomicBool

	buf  bytes.Buffer
	recv chan []byte
}

var _ net.Conn = &Conn{}

var ErrWouldBlock = errors.New("temporary err would block")

func (c *Conn) lockUser() {
	c.m.Lock()
	c.readLock.Lock()
	c.writeLock.Lock()
}

func (c *Conn) unlockUser() {
	c.m.Unlock()
	c.writeLock.Unlock()
	c.readLock.Unlock()
}

func (c *Conn) Read(b []byte) (int, error) {
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
	// TODO(dadrian): This is non-blocking, we need to see if we can make it blocking
	// TODO(dadrian): Handle timeouts
	var msg []byte
	select {
	case msg = <-c.recv:
		break
	default:
		if c.closed.isSet() {
			return 0, io.EOF
		}
		return 0, ErrWouldBlock
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

func (c *Conn) Write(b []byte) (int, error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	return 0, nil
}

func (c *Conn) Close() error {
	c.lockUser()
	defer c.unlockUser()

	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	c.lockUser()
	defer c.unlockUser()

	return nil
}

func (c *Conn) RemoteAddr() net.Addr {
	c.lockUser()
	defer c.unlockUser()

	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.lockUser()
	defer c.unlockUser()

	return nil
}

// SetReadDeadline implements net.Conn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.lockUser()
	defer c.unlockUser()

	return nil
}

// SetWriteDeadline implements net.Conn.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.lockUser()
	defer c.unlockUser()

	return nil
}
