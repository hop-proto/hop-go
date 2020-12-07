package main

import (
	"net"
	"time"
	//"errors"
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
	cid int
	ca *chanApp
	statusMut sync.Mutex
	rDMut sync.Mutex
	rDeadline time.Time
	wDMut sync.Mutex
	wDeadline time.Time
}

func (c *Channel) Read(b []byte) (int, error) {
	return 0, nil
}

func (c *Channel) Write(b []byte) (int, error) {
	return 0, nil
}

func (c *Channel) Close() error {
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
