package transport

import (
	"io"
	"net"
	"os"
	"time"
	"sync"
	"context"
	"errors"
)

// ReliableUDP is an in memory reliable datagram service
// Essentially, it's a UDP connection where every datagram is delivered reliably and in order
// This is only used for testing purposes
type ReliableUDP struct {
	send 			chan []byte
	recv 			chan []byte
	closed 			atomicBool
	dataLock		sync.Mutex
	timeoutLock		sync.Mutex

	readCtx			context.Context
	readCancel 		context.CancelFunc

	writeCtx 		context.Context
	writeCancel		context.CancelFunc
}

var _ UDPLike = &ReliableUDP{}

func (r *ReliableUDP) Read(b []byte) (n int, err error) {
	n, _, _, _, err = r.ReadMsgUDP(b, nil)
	return n, err
}

func (r *ReliableUDP) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	r.dataLock.Lock()
	defer r.dataLock.Unlock()

	if r.closed.isSet() {
		return 0, 0, 0, nil, io.EOF
	}

	select {
	case <- r.readCtx.Done():
		return 0, 0, 0, nil, os.ErrDeadlineExceeded
	default:
	}

	for {
		select {
		case msg, ok := <- r.recv:
			if !ok {
				return 0, 0, 0, nil, io.EOF
			}
			n = copy(b, msg)
			if n < len(msg) {
				panic("buffer too small!")
			}
			return n, 0, 0, nil, nil
		case <-r.readCtx.Done():
			err := r.readCtx.Err()
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, 0, 0, nil, os.ErrDeadlineExceeded
			} else if err == nil || errors.Is(err, context.Canceled) {
				continue
			} else {
				panic(err)
			}
		}
	}
}

func (r *ReliableUDP) Write(b []byte) (n int, err error) {
	n, _, err = r.WriteMsgUDP(b, nil, nil)
	return n, err
}

func (r *ReliableUDP) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	r.dataLock.Lock()
	defer r.dataLock.Unlock()

	if r.closed.isSet() {
		return 0, 0, io.EOF
	}

	select {
	case <- r.writeCtx.Done():
		return 0, 0, os.ErrDeadlineExceeded
	default:
	}

	for {
		select {
		case r.send <-append([]byte(nil), b...):
			return len(b), 0, nil
		case <-r.writeCtx.Done():
			err := r.writeCtx.Err()
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, 0, os.ErrDeadlineExceeded
			} else if errors.Is(err, context.Canceled) {
				continue
			} else {
				panic(err)
			}
		}
	}
}

func (r *ReliableUDP) Close() error {
	//r.l.Lock()
	//defer r.l.Unlock()

	r.SetDeadline(time.Unix(1, 0))

	if r.closed.isSet() {
		return io.EOF
	}
	close(r.send)
	r.closed.setTrue()
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

	r.readCancel()

	if t.IsZero() {
		r.readCtx, r.readCancel = context.WithCancel(context.Background())
	} else {
		select {
		case <- r.readCtx.Done():
			r.readCtx, r.readCancel = context.WithDeadline(context.Background(), t)
		default:
			r.readCtx, r.readCancel = context.WithDeadline(r.readCtx, t)
		}
	}

	return nil
}

func (r *ReliableUDP) SetWriteDeadline(t time.Time) error {
	r.timeoutLock.Lock()
	defer r.timeoutLock.Unlock()

	r.writeCancel()

	if t.IsZero() {
		r.writeCtx, r.writeCancel = context.WithCancel(context.Background())
	} else {
		select {
		case <- r.writeCtx.Done():
			r.writeCtx, r.writeCancel = context.WithDeadline(context.Background(), t)
		default:
			r.writeCtx, r.writeCancel = context.WithDeadline(r.writeCtx, t)
		}
	}

	return nil
}

func MakeRelaibleUDPConn() (c1, c2 *ReliableUDP) {
	ch1 := make(chan []byte, 1 << 16)
	ch2 := make(chan []byte, 1 << 16)

	c1ReadCtx, c1ReadCancel := context.WithCancel(context.Background())
	c1WriteCtx, c1WriteCancel := context.WithCancel(context.Background())
	c1 = &ReliableUDP {
		send: ch1,
		recv: ch2,
		readCtx: c1ReadCtx,
		readCancel: c1ReadCancel,
		writeCtx: c1WriteCtx,
		writeCancel: c1WriteCancel,
	}

	c2ReadCtx, c2ReadCancel := context.WithCancel(context.Background())
	c2WriteCtx, c2WriteCancel := context.WithCancel(context.Background())
	c2 = &ReliableUDP {
		send: ch2,
		recv: ch1,
		readCtx: c2ReadCtx,
		readCancel: c2ReadCancel,
		writeCtx: c2WriteCtx,
		writeCancel: c2WriteCancel,
	}

	return c1, c2
}
