package transport

import (
	"io"
	"net"
	"os"
	"time"
	"sync"

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
	closed 			common.AtomicBool
	readLock		sync.Mutex
	writeLock		sync.Mutex
	timeoutLock		sync.Mutex

	// +checklocks:timeoutLock
	readTimer 		*time.Timer
	readExpired		common.AtomicBool

	// +checklocks:timeoutLock
	writeTimer 		*time.Timer
	writeExpired	common.AtomicBool
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

	for {
		if r.closed.IsSet() {
			return 0, 0, 0, addr, io.EOF
		}
		if r.readExpired.IsSet() {
			return 0, 0, 0, addr, os.ErrDeadlineExceeded
		}
		select {
		case msg, ok := <- r.recv: 
			if !ok {
				return 0, 0, 0, addr, io.EOF
			}
			n = copy(b, msg)
			if n < len(msg) {
				panic("buffer too small!")
			}
			return n, 0, 0, addr, nil
		default:
			time.Sleep(time.Millisecond)
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

	for {
		if r.closed.IsSet() {
			return 0, 0, io.EOF
		}
		if r.writeExpired.IsSet() {
			return 0, 0, os.ErrDeadlineExceeded
		}
		select {
		case r.send <-append([]byte(nil), b...):
			return len(b), 0, nil
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func (r *ReliableUDP) Close() error {
	if r.closed.IsSet() {
		return io.EOF
	}

	r.closed.SetTrue()
	r.timeoutLock.Lock()
	r.readLock.Lock()
	r.writeLock.Lock()
	defer r.timeoutLock.Unlock()
	defer r.readLock.Unlock()
	defer r.writeLock.Unlock()

	//time.Sleep(time.Millisecond)

	close(r.send)
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
	r.timeoutLock.Lock()
	defer r.timeoutLock.Unlock()

	if r.readTimer != nil {
		if !r.readTimer.Stop() {
			select {
			case <-r.readTimer.C:
			default:
			}
		}
	}


	if t.IsZero() {
		r.readExpired.SetFalse()
	} else if t.Before(time.Now()) {
		r.readExpired.SetTrue()
	} else {
		r.readExpired.SetFalse()
		if r.readTimer != nil {
			r.readTimer.Reset(t.Sub(time.Now()))
		} else {
			f := func() {
				r.readExpired.SetTrue()
			}
			r.readTimer = time.AfterFunc(t.Sub(time.Now()), f)
		}

	}

	return nil
}

func (r *ReliableUDP) SetWriteDeadline(t time.Time) error {
	r.timeoutLock.Lock()
	defer r.timeoutLock.Unlock()

	if r.writeTimer != nil {
		if !r.writeTimer.Stop() {
			select {
			case <-r.writeTimer.C:
			default:
			}
		}
	}


	if t.IsZero() {
		r.writeExpired.SetFalse()
	} else if t.Before(time.Now()) {
		r.writeExpired.SetTrue()
	} else {
		r.writeExpired.SetFalse()
		if r.writeTimer != nil {
			r.writeTimer.Reset(t.Sub(time.Now()))
		} else {
			f := func() {
				r.writeExpired.SetTrue()
			}
			r.writeTimer = time.AfterFunc(t.Sub(time.Now()), f)
		}

	}

	return nil
}

func MakeRelaibleUDPConn() (c1, c2 *ReliableUDP) {
	ch1 := make(chan []byte, 1 << 16)
	ch2 := make(chan []byte, 1 << 16)

	c1 = &ReliableUDP {
		send: ch1,
		recv: ch2,
	}

	c2 = &ReliableUDP {
		send: ch2,
		recv: ch1,
	}

	return c1, c2
}
