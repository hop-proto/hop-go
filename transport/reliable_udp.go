package transport

import (
	"io"
	"net"
	"sync"
	"time"

	"hop.computer/hop/common"
)

// ReliableUDP is an in memory reliable datagram service
// Essentially, it's a UDP connection where every datagram is delivered reliably and in order
// This is only used for testing purposes
type ReliableUDP struct {
	// +checklocks:writeLock
	send 			chan []byte
	// +checklocks:readLock
	recv 			chan []byte
	readLock		sync.Mutex
	writeLock		sync.Mutex

	readDeadline 	*common.Deadline
	writeDeadline 	*common.Deadline

	closed 			common.AtomicBool
}

var _ UDPLike = &ReliableUDP{}

func (r *ReliableUDP) Read(b []byte) (n int, err error) {
	n, _, _, _, err = r.ReadMsgUDP(b, nil)
	return n, err
}

func (r *ReliableUDP) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	r.readLock.Lock()
	defer r.readLock.Unlock()

	addr = &net.UDPAddr{}

	if r.closed.IsSet() {
		return 0, 0, 0, addr, io.EOF
	}

	ch := r.readDeadline.Done()
	select {
	case err = <-ch:
		return
	default:
		select {
		case err = <-ch:
			return
		case msg, ok := <- r.recv: 
			if !ok {
				err = io.EOF
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

func (r *ReliableUDP) Write(b []byte) (n int, err error) {
	n, _, err = r.WriteMsgUDP(b, nil, nil)
	return n, err
}

func (r *ReliableUDP) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	r.writeLock.Lock()
	defer r.writeLock.Unlock()

	if r.closed.IsSet() {
		err = io.EOF
		return
	}

	// This is how we give priority to receiving from Done over sending on send
	select {
	case err = <-r.writeDeadline.Done():
		return
	default:
		select {
		case err = <-r.writeDeadline.Done():
			return
		case r.send <-append([]byte(nil), b...):
			n = len(b)
			return
		}
	}
}

func (r *ReliableUDP) Close() error {
	if r.closed.IsSet() {
		return io.EOF
	}

	r.closed.SetTrue()
	r.writeDeadline.Cancel(io.EOF)
	r.readDeadline.Cancel(io.EOF)

	r.writeLock.Lock()
	defer r.writeLock.Unlock()

	//close(r.send)
	return nil
}

func (r *ReliableUDP) LocalAddr() net.Addr {
	return nil
}

func (r *ReliableUDP) RemoteAddr() net.Addr {
	return nil
}

func (r *ReliableUDP) SetDeadline(t time.Time) error {
	r.SetReadDeadline(t)
	r.SetWriteDeadline(t)
	return nil
}

func (r *ReliableUDP) SetReadDeadline(t time.Time) error {
	return r.readDeadline.SetDeadline(t)
}

func (r *ReliableUDP) SetWriteDeadline(t time.Time) error {
	return r.writeDeadline.SetDeadline(t)
}

func MakeRelaibleUDPConn() (c1, c2 *ReliableUDP) {
	ch1 := make(chan []byte, 1 << 16)
	ch2 := make(chan []byte, 1 << 16)

	c1 = &ReliableUDP {
		send: ch1,
		recv: ch2,
		readDeadline: common.NewDeadline(time.Time{}),
		writeDeadline: common.NewDeadline(time.Time{}),
	}

	c2 = &ReliableUDP {
		send: ch2,
		recv: ch1,
		readDeadline: common.NewDeadline(time.Time{}),
		writeDeadline: common.NewDeadline(time.Time{}),
	}

	return c1, c2
}
