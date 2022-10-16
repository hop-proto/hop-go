package transport

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"hop.computer/hop/common"
)

// ReliableUDP is an in memory reliable datagram service
// Essentially, it's a UDP connection where every datagram is delivered reliably and in order
// This is only used for testing purposes
type ReliableUDP struct {
	// +checklocks:writeLock
	send chan []byte
	// +checklocks:readLock
	recv      chan []byte
	readLock  sync.Mutex
	writeLock sync.Mutex

	readDeadline  *common.Deadline
	writeDeadline *common.Deadline

	closed atomic.Bool

	eof bool
}

var _ UDPLike = &ReliableUDP{}
var _ MsgConn = &ReliableUDP{}

// Read reads data into b
func (r *ReliableUDP) Read(b []byte) (n int, err error) {
	n, _, _, _, err = r.ReadMsgUDP(b, nil)
	return n, err
}

// ReadMsg implements the MsgConn interface
func (r *ReliableUDP) ReadMsg(b []byte) (n int, err error) {
	return r.Read(b)
}

// ReadMsgUDP implements to UDPLike interface
func (r *ReliableUDP) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	r.readLock.Lock()
	defer r.readLock.Unlock()

	addr = &net.UDPAddr{}

	// return buffered packets even after closed
	select {
	case msg, ok := <-r.recv:
		if !ok {
			err = io.EOF
			return
		}
		n = copy(b, msg)
		if n < len(msg) {
			panic("buffer too small")
		}
		return
	default:
		break
	}

	if r.closed.Load() {
		return 0, 0, 0, addr, net.ErrClosed
	}

	ch := r.readDeadline.Done()
	select {
	case <-ch:
		err = r.readDeadline.Err()
		return
	default:
		select {
		case <-ch:
			err = r.readDeadline.Err()
			return
		case msg, ok := <-r.recv:
			if !ok {
				err = net.ErrClosed
				return
			}
			n = copy(b, msg)
			if n < len(msg) {
				panic("buffer too small!")
			}
			return
		}
	}
}

// Write writes data to the connection
func (r *ReliableUDP) Write(b []byte) (n int, err error) {
	n, _, err = r.WriteMsgUDP(b, nil, nil)
	return n, err
}

// WriteMsg implements the MsgConn interface
func (r *ReliableUDP) WriteMsg(b []byte) (err error) {
	_, err = r.Write(b)
	return
}

// WriteMsgUDP implements the UDPLike interface
func (r *ReliableUDP) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	r.writeLock.Lock()
	defer r.writeLock.Unlock()

	if r.closed.Load() {
		err = net.ErrClosed
		return
	}

	// This is how we give priority to receiving from Done over sending on send
	select {
	case <-r.writeDeadline.Done():
		err = r.writeDeadline.Err()
		return
	default:
		select {
		case <-r.writeDeadline.Done():
			err = r.writeDeadline.Err()
			return
		case r.send <- append([]byte(nil), b...):
			n = len(b)
			return
		}
	}
}

// Close closes the connection and cancels pending reads and writes.
// Reads from the remote host will not return io.EOF since there is no
// closing behavior defined in UDP
func (r *ReliableUDP) Close() error {
	if r.closed.Load() {
		return net.ErrClosed
	}

	r.closed.Store(true)
	r.writeDeadline.Cancel(net.ErrClosed)
	r.readDeadline.Cancel(net.ErrClosed)

	r.writeLock.Lock()
	defer r.writeLock.Unlock()

	if r.eof {
		close(r.send)
	}
	return nil
}

// LocalAddr implements to UDPLike interface
func (r *ReliableUDP) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr implements to UDPLike interface
func (r *ReliableUDP) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline implements to UDPLike interface
func (r *ReliableUDP) SetDeadline(t time.Time) error {
	r.SetReadDeadline(t)
	r.SetWriteDeadline(t)
	return nil
}

// SetReadDeadline implements to UDPLike interface
func (r *ReliableUDP) SetReadDeadline(t time.Time) error {
	return r.readDeadline.SetDeadline(t)
}

// SetWriteDeadline implements to UDPLike interface
func (r *ReliableUDP) SetWriteDeadline(t time.Time) error {
	return r.writeDeadline.SetDeadline(t)
}

// MakeReliableUDPConn returns two pointers to ReliableUDP structs
// Writes and reads from one connection can be seen on the other one
// eof is true if closing one end of the connection should cause reads from the other to return io.EOF
func MakeReliableUDPConn(eof bool) (c1, c2 *ReliableUDP) {
	ch1 := make(chan []byte, 1<<16)
	ch2 := make(chan []byte, 1<<16)

	c1 = &ReliableUDP{
		send:          ch1,
		recv:          ch2,
		readDeadline:  common.NewDeadline(time.Time{}),
		writeDeadline: common.NewDeadline(time.Time{}),
		eof:           eof,
	}

	c2 = &ReliableUDP{
		send:          ch2,
		recv:          ch1,
		readDeadline:  common.NewDeadline(time.Time{}),
		writeDeadline: common.NewDeadline(time.Time{}),
		eof:           eof,
	}

	return c1, c2
}
