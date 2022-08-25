package transport

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
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

	// +checklocks:m
	state connState
	m     sync.Mutex
	waitTimer *time.Timer
	closed    chan struct{}

	// +checklocks:readLock
	buf bytes.Buffer

	ss     *SessionState
	server *Server
}

var _ MsgReader = &Handle{}
var _ MsgWriter = &Handle{}
var _ MsgConn = &Handle{}

var _ net.Conn = &Handle{}

func (c *Handle) GetState() connState {
	c.m.Lock()
	defer c.m.Unlock()
	return c.state
}

// IsClosed returns true if the handle is closed or in the process of closing.
// Writes and reads to the handle return io.EOF if and only if IsClosed returns true
func (c *Handle) IsClosed() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.state != established && c.state != closeWait
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

	if c.IsClosed() {
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
	if c.IsClosed() {
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

// writeControl writes a control message to the remote host
func (c *Handle) writeControl(msg ControlMessage) error {
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
	}
}

func (c *Handle) handleControl(msg []byte) (err error) {
	if len(msg) != 1 {
		logrus.Error("handle: invalid control message: ", msg)
		c.Reset()
		return ErrInvalidMessage
	}

	c.m.Lock()
	defer c.m.Unlock()

	ctrlMsg := ControlMessage(msg[0])
	switch ctrlMsg {

	case ControlMessageClose:
		logrus.Debug("handle: got close message")
		if c.state == established {
			logrus.Debug("handle: established->closeWait")
			c.state = closeWait
		} else if c.state == finWait1 {
			logrus.Debug("handle: finWait1->closing")
			c.state = closing
		} else if c.state == finWait2 {
			logrus.Debug("handle: finWait2->timeWait")
			c.state = timeWait
			if c.waitTimer == nil {
				c.waitTimer = time.AfterFunc(5 * time.Second, func() {
					logrus.Debug("handle: finished lingering")
					c.closed <- struct{}{}
				})
			}
		} else {
			logrus.Debugf("handle: got close in invalid state: %d", c.state)
			err = ErrInvalidMessage
		}
		c.recv.Close()
		c.writeControl(ControlMessageAckClose)
		go c.Close()
		return

	case ControlMessageAckClose:
		logrus.Debug("handle: got ack of close")
		if c.state == finWait1 {
			logrus.Debug("handle: finWait1->finWait2")
			c.state = finWait2
		} else if c.state == closing {
			logrus.Debug("handle: closing->timeWait")
			c.state = timeWait
			if c.waitTimer == nil {
				c.waitTimer = time.AfterFunc(5 * time.Second, func() {
					logrus.Debug("handle: finished lingering")
					c.closed <- struct{}{}
				})
			}
		} else if c.state == lastAck {
			logrus.Debug("handle: lastAck->closed")
			c.state = closed
			c.closed <- struct{}{}
		} else {
			logrus.Debugf("handle: got ack of fin in invalid state: %d", c.state)
			return ErrInvalidMessage
		}
		return nil

	case ControlMessageReset:
		logrus.Errorf("server: connection reset by remote peer")
		c.server.m.Lock()
		defer c.server.m.Unlock()
		return c.shutdown()

	default:
		logrus.Errorf("server: unexpected control message: %x", msg)
		c.Reset()
		return ErrInvalidMessage
	}
}

// Start starts the goroutines that handle messages
func (c *Handle) Start() {
	c.m.Lock()
	defer c.m.Unlock()

	c.state = established
	c.closed = make(chan struct{})

	c.sendWg.Add(1)
	go c.sender()
}

// Reset closes the connection without waiting for graceful shutdown
func (c *Handle) Reset() error {
	c.writeControl(ControlMessageReset)

	c.m.Lock()
	defer c.m.Unlock()

	c.server.m.Lock()
	defer c.server.m.Unlock()
	return c.shutdown()
}

// Close closes the connection. Future operations on non-buffered data will
// return io.EOF.
func (c *Handle) Close() error {
	c.m.Lock()
	defer c.m.Unlock()
	
	switch c.state {
	case established:
		logrus.Debug("handle: established->finWait1")
		c.state = finWait1
	case closeWait:
		logrus.Debug("handle: closeWait->lastAck")
		c.state = lastAck
	default:
		return io.EOF
	}

	logrus.Debug("handle: starting close")

	c.writeControl(ControlMessageClose)

	c.m.Unlock()
	<-c.closed
	c.m.Lock()

	c.server.m.Lock()
	defer c.server.m.Unlock()
	return c.shutdown()

	/*
	 * Two cases, either we have gotten a fin before this or we have not
	 * 
	 * if we have, send an ACK (in handle control)
	 * send our fin
	 * wait for an ack
	 * retransmit if needed
	 * if we get an ACK, end immediately
	 * otherwise, timeout
	 *
	 * if we have not gotten a fin yet,
	 * send our fin
	 * wait for both a fin and an ack
	 * when we get both, linger for a bit
	 * clean everything up
	 * the server shouldn't care if this blocks for a while
	 */
}

// Note that the lock here refers to the server's lock
// +checklocks:c.server.m
// +checklocks:c.m
func (c *Handle) shutdown() error {
	c.recv.Close()
	c.send.Close()

	// Wait for the sending goroutines to exit
	c.sendWg.Wait()

	c.state = closed

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
