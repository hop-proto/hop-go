package main

import (
	"net"
	"time"
	"errors"
	"sync"
	"strconv"
)

// Implements Addr Interface
type ChAddr struct {
	cid int
}

func (ad *ChAddr) Network() string {
	return "channel"
}

func (ad *ChAddr) String() string {
	return strconv.Itoa(ad.cid)
}

// Implements Conn interface
type Channel struct {
	// Channel ID
	cid int
	// Pointer to Internal Chan App
	ca *chanApp
	// Read Deadline Mut / Time
	rDMut sync.Mutex
	rDeadline time.Time
	// Write Deadline Mut / Time
	wDMut sync.Mutex
	wDeadline time.Time
	// Go Channel used to signal
	// Read/Writes to exit
	closeRW chan struct{}
	// Mutex & bool for closing
	mu sync.Mutex
	closed bool
}

func (c *Channel) Read(b []byte) (int, error) {
	var deadline time.Time
	c.rDMut.Lock()
	deadline = c.rDeadline
	c.rDMut.Unlock()
	select {
		case <-c.closeRW:
			return 0, errors.New("Channel has closed")
		default:
			select {
				case <-c.closeRW:
					return 0, errors.New("Channel has closed")
				case data, ok := <-c.ca.channelReadChs[c.cid]:
					if !ok {
						return 0, errors.New("Channel Application has closed")
					}
					copy(b, data)
					return len(data), nil
				case <-time.After(time.Until(deadline)):
					return 0, errors.New("Read Deadline exceeded")
			}
	}
}

func (c *Channel) Write(b []byte) (int, error) {
	var deadline time.Time
	c.wDMut.Lock()
	deadline = c.wDeadline
	c.wDMut.Unlock()
	select {
		case <-c.closeRW:
			return 0, errors.New("Channel has closed")
		default:
			select {
				case <-c.closeRW:
					return 0, errors.New("Channel has closed")
				case c.ca.channelWriteChs[c.cid] <- b:
					c.ca.channelSendConds[c.cid].Signal()
					return len(b), nil
				case <-time.After(time.Until(deadline)):
					return 0, errors.New("Write Deadline exceeded")
			}
	}
}

func (c *Channel) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("Channel already closed")
	}
	close(c.closeRW)
	c.closed = true
	return nil
}

func (c *Channel) LocalAddr() net.Addr {
	return &ChAddr{c.cid}
}

func (c *Channel) RemoteAddr() net.Addr {
	return &ChAddr{c.cid}
}

func (c *Channel) SetDeadline(t time.Time) error {
	c.rDMut.Lock()
	c.wDMut.Lock()
	defer c.rDMut.Unlock()
	defer c.wDMut.Unlock()

	c.rDeadline = t
	c.wDeadline = t

	return nil
}

func (c *Channel) SetReadDeadline(t time.Time) error {
	c.rDMut.Lock()
	defer c.rDMut.Unlock()

	c.rDeadline = t

	return nil
}

func (c *Channel) SetWriteDeadline(t time.Time) error {
	c.wDMut.Lock()
	defer c.wDMut.Unlock()

	c.wDeadline = t

	return nil
}
