package transport

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type IEndpoint interface {
	LocalAddr() (*net.UDPAddr, error)
	Listen() error
	Accept() (net.Conn, error)
	Close() error
}

var ErrUnbound = errors.New("endpoint not yet bound")
var ErrListen = errors.New("endpoint not in listen mode")
var ErrConnected = errors.New("endpoint is already connected")
var ErrWouldBlock = errors.New("action would block")
var ErrClosed = errors.New("cannot write to closed connection")

type EndpointState uint32

const (
	StateInital = iota
	StateBound
	StateListening
	StateConnected
	StateClosed
)

type Endpoint struct {
	state      EndpointState
	stateMutex sync.Mutex

	acceptMutex sync.Mutex

	underlying *net.UDPConn

	pendingConnections chan net.Conn
}

var _ IEndpoint = &Endpoint{}

type Conn struct {
	m   sync.Mutex
	buf bytes.Buffer

	recv chan []byte
	send chan []byte
	sent chan int

	open bool
}

var _ net.Conn = &Conn{}

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
	// TODO(dadrian): This is non-blocking, we need to see if we can make it blocking
	// TODO(dadrian): Handle timeouts
	var msg []byte
	select {
	case msg = <-c.recv:
		break
	default:
		if !c.open {
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
	c.m.Lock()
	defer c.m.Unlock()
	if !c.open {
		return 0, ErrClosed
	}
	// TODO(dadrian): Make the this work with blocking calls
	select {
	case c.send <- b:
		break
	default:
		return 0, ErrWouldBlock
	}
	<-c.sent
	return len(b), nil
}

func (c *Conn) Close() error {
	c.m.Lock()
	defer c.m.Unlock()
	// NB: Note that Reads can still succeed after this, if data is buffered. Is
	// that OK?
	// TODO(dadrian): Figure out what the behavior with pending calls and
	// buffered data is with TCP in Go, and match it.
	c.open = false
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	// TODO(dadrian): What should this return? A UDP address, or a $NAME
	// address?
	return nil
}

func (c *Conn) RemoteAddr() net.Addr {
	// TODO(dadrian): What should this return? A UDP address, or a $NAME
	// address?
	return nil
}

func (c *Conn) SetDeadline(deadline time.Time) error {
	// TODO(dadrian): This only makes sense once Read() and Write() are blocking.
	return nil
}

func (c *Conn) SetReadDeadline(deadline time.Time) error {
	// TODO(dadrian): This only makes sense once Read() is blocking.
	return nil
}

func (c *Conn) SetWriteDeadline(deadline time.Time) error {
	// TODO(dadrian): This only makes sense once Write() is blocking.
	return nil
}

// LocalAddr returns the address of the underlying net.UDPConn. If the Endpoint
// is not yet bound, it returns ErrUnbound.
func (e *Endpoint) LocalAddr() (*net.UDPAddr, error) {
	e.stateMutex.Lock()
	defer e.stateMutex.Unlock()

	if e.state == StateInital {
		return nil, ErrUnbound
	}

	netAddr := e.underlying.LocalAddr()
	return netAddr.(*net.UDPAddr), nil
}

func (e *Endpoint) Accept() (net.Conn, error) {
	e.stateMutex.Lock()
	defer e.stateMutex.Lock()
	if e.state != StateListening {
		return nil, ErrListen
	}
	e.acceptMutex.Lock()
	defer e.acceptMutex.Unlock()

	select {
	case c := <-e.pendingConnections:
		return c, nil
	default:
		return nil, ErrWouldBlock
	}
}

func (e *Endpoint) isBound() bool {
	return e.underlying != nil
}

func (e *Endpoint) Listen() error {
	e.stateMutex.Lock()
	defer e.stateMutex.Unlock()
	if !e.isBound() {
		return ErrUnbound
	}
	if e.state == StateListening {
		return nil
	}
	if e.state == StateConnected {
		return ErrConnected
	}
	e.state = StateListening
	// Do listen
	return nil
}

func (e *Endpoint) Close() error {
	e.stateMutex.Lock()
	defer e.stateMutex.Unlock()
	if e.pendingConnections != nil {
		close(e.pendingConnections)
	}
	if e.underlying != nil {
		e.underlying.Close()
	}
	e.state = StateClosed
	return nil
}
