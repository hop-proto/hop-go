package main

import (
	"net"
	"time"
	"errors"
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
	ca *ChanApp
	cid int
	hasRDL bool
	hasWDL bool
	readDL time.Time
	writeDL time.Time
}

func (c *Channel) Read(b []byte) (int, error) {
	if c.hasRDL {
		ch := make(chan struct {data []byte; ok bool}, 1)
		go func() {
			data, ok := c.ca.readCh(c.cid)
			ch <- struct{data []byte; ok bool}{data, ok}
			close(ch)
		}()
		result := struct{data []byte; ok bool}{[]byte{}, false}
		timeout := false
		select {
			case result = <- ch:
			case <- time.After(time.Until(c.readDL)):
				timeout = true
		}
		if result.ok {
			copy(b, result.data)
			return len(result.data), nil
		} else if !timeout {
			return 0, errors.New("Channel Read is Closed")
		}
		return 0, errors.New("Channel Read Timeout")
	} else {
		data, ok := c.ca.readCh(c.cid)
		if ok {
			copy(b, data)
			return len(data), nil
		}
		return 0, errors.New("Channel Read is Closed")
	}
}

func (c *Channel) Write(b []byte) (int, error) {
	if c.hasWDL {
		ch := make(chan bool, 1)
		go func() {
			c.ca.writeCh(c.cid, b)
			ch <- true
			close(ch)
		}()
		timeout := false
		select {
			case <- ch:
			case <- time.After(time.Until(c.writeDL)):
				timeout = true
		}
		if !timeout {
			return len(b), nil
		}
		return 0, errors.New("Channel Write Timeout")
	} else {
		c.ca.writeCh(c.cid, b)
		return len(b), nil
	}
}

// Need to send FIN?
// Does not necessarily terminate ongoing read/writes
func (c *Channel) Close() error {
	c.ca = nil
	return nil
}

func (c *Channel) LocalAddr() net.Addr {
	return &ChAddr{c.cid}
}

func (c *Channel) RemoteAddr() net.Addr {
	return &ChAddr{c.cid}
}

func (c *Channel) SetDeadline(t time.Time) error {
	c.readDL = t
	c.writeDL = t
	c.hasRDL = true
	c.hasWDL = true
	return nil
}

func (c *Channel) SetReadDeadline(t time.Time) error {
	c.readDL = t
	c.hasRDL = true
	return nil
}

func (c *Channel) SetWriteDeadline(t time.Time) error {
	c.writeDL = t
	c.hasWDL = true
	return nil
}
