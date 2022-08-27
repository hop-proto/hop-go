package common

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Deadline implements a deadline following the requirements of the net.Conn
// SetDeadline method. It allows the deadline to be extended and allows
// an expired deadline to become unexpired.
type Deadline struct {
	chanLock sync.Mutex
	// +checklocks:chanLock
	chans []chan error

	timerLock sync.Mutex
	// +checklocks:timerLock
	timer *time.Timer

	active atomic.Bool

	// +checklocks:chanLock
	err error
}

// Done returns a channel. The Deadline will send an error on the channel
// when the deadline is exceeded or Cancel is called.
// This allows a function to select on either the deadline or another channel
func (d *Deadline) Done() chan error {
	d.chanLock.Lock()
	defer d.chanLock.Unlock()
	// TODO(hosono) avoid leaking channels
	ch := make(chan error, 1)
	if !d.active.Load() {
		ch <- d.err
		close(ch)
	} else {
		d.chans = append(d.chans, ch)
	}
	return ch
}

// Cancel send err to every channel created by calling Done
// This allows selects statements to return before the deadline expires
func (d *Deadline) Cancel(err error) {
	d.chanLock.Lock()
	defer d.chanLock.Unlock()

	d.active.Store(false)
	d.err = err

	for _, ch := range d.chans {
		ch <- err
		close(ch)
	}

	d.chans = nil
}

func (d *Deadline) timeout() {
	d.Cancel(os.ErrDeadlineExceeded)
}

// SetDeadline sets a new time at which the deadline will expire.
// t will override the current deadline regardless of whether it is
// before or after the current deadline. Calling SetDeadline with
// the zero value for time.Time will cause the deadline to never expire
func (d *Deadline) SetDeadline(t time.Time) error {
	d.timerLock.Lock()
	defer d.timerLock.Unlock()

	if !d.timer.Stop() {
		select {
		case <-d.timer.C:
			break
		default:
			break
		}
	}

	if t.IsZero() {
		d.active.Store(true)
		return nil
	}

	start := time.Now()
	if t.Before(start) {
		d.timeout()
	} else {
		d.active.Store(true)
		d.timer.Reset(t.Sub(start))
	}

	return nil
}

// NewDeadline returns a pointer to a new deadline expiring at time t
func NewDeadline(t time.Time) *Deadline {
	d := &Deadline{}
	d.timer = time.AfterFunc(time.Hour, d.timeout)
	if !d.timer.Stop() {
		<-d.timer.C
	}
	d.active.Store(true)
	d.SetDeadline(t)
	return d
}

// DeadlineChan is a channel of byte slices attached to a deadline.
// It allows a caller to read and write from the channel,
// But pending reads and writes can time out or be canceled
type DeadlineChan[T any] struct {
	deadline *Deadline
	closed   atomic.Bool
	C        chan T
}

// Recv reads one byte slice from the underlying channel
// If the deadline is exceeded, Cancel is called, or Close is called,
// err will be set to a relevant error. Always check that err is nil before using b
func (d *DeadlineChan[T]) Recv() (b T, err error) {
	// Return buffered data even if the channel is canceled
	select {
	case b = <-d.C:
		return
	default:
		break
	}

	if d.closed.Load() {
		err = io.EOF
		return
	}

	errChan := d.deadline.Done()
	select {
	case err = <-errChan:
		return
	default:
		select {
		case err = <-errChan:
			return
		case b = <-d.C:
			return
		}
	}
}

// Send send one byte slice on the underlying channel
// If the deadline is exceeded, Cancel is called, or Close is called,
// err will not be nil.
func (d *DeadlineChan[T]) Send(b T) (err error) {
	if d.closed.Load() {
		return io.EOF
	}

	errChan := d.deadline.Done()
	select {
	case err = <-errChan:
		return
	default:
		select {
		case err = <-errChan:
			return
		case d.C <- b:
			return
		}
	}
}

// SetDeadline sets a time at which calls to Send and Recv will timeout
func (d *DeadlineChan[T]) SetDeadline(t time.Time) error {
	if d.closed.Load() {
		return io.EOF
	}
	return d.deadline.SetDeadline(t)
}

// Cancel cancels pending calls to Send and Recv and causes them to return err
// TODO(hosono) when should Recv return buffered data
func (d *DeadlineChan[T]) Cancel(err error) error {
	if d.closed.Load() {
		return io.EOF
	}
	d.deadline.Cancel(err)
	return nil
}

// Close cancels pending calls to Send and Recv. Those calls will return
// io.EOF rather than os.ErrDeadlineExceeded even after the deadline has expired
func (d *DeadlineChan[T]) Close() error {
	if d.closed.Load() {
		return io.EOF
	}
	d.closed.Store(true)
	d.deadline.Cancel(io.EOF)
	return nil
}

// NewDeadlineChan returns a pointer to a DeadlineChan with capacity of size
func NewDeadlineChan[T any](size int) *DeadlineChan[T] {
	return &DeadlineChan[T]{
		deadline: NewDeadline(time.Time{}),
		C:        make(chan T, size),
	}
}
