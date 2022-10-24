package common

import (
	"io"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Deadline implements a deadline following the requirements of the net.Conn
// SetDeadline method. It allows the deadline to be extended and allows
// an expired deadline to become unexpired.
type Deadline struct {
	m sync.Mutex

	// +checklocks:m
	ch chan struct{}

	// +checklocks:m
	timer *time.Timer

	// +checklocks:m
	err error
}

// Done returns a channel. The Deadline will send an error on the channel
// when the deadline is exceeded or Cancel is called.
// This allows a function to select on either the deadline or another channel
func (d *Deadline) Done() <-chan struct{} {
	d.m.Lock()
	defer d.m.Unlock()
	return d.ch
}

// Cancel sends err to every channel created by calling Done
// This allows selects statements to return before the deadline expires
func (d *Deadline) Cancel(err error) {
	d.m.Lock()
	defer d.m.Unlock()

	d.err = err

	select {
	case <-d.ch:
		break
	default:
		close(d.ch)
	}
}

// Err returns the type of error that last caused the deadline to expire
// TODO(hosono) there's technically a race condition here because the error
// is not checked at the same time a channel signals done. Is this a real problem?
func (d *Deadline) Err() error {
	d.m.Lock()
	defer d.m.Unlock()
	return d.err
}

func (d *Deadline) timeout() {
	d.Cancel(os.ErrDeadlineExceeded)
}

// SetDeadline sets a new time at which the deadline will expire.
// t will override the current deadline regardless of whether it is
// before or after the current deadline. Calling SetDeadline with
// the zero value for time.Time will cause the deadline to never expire
func (d *Deadline) SetDeadline(t time.Time) error {
	d.m.Lock()
	defer d.m.Unlock()

	if !d.timer.Stop() {
		select {
		case <-d.timer.C:
			break
		default:
			break
		}
	}

	// Replace the channel to unexpire it
	select {
	case _, ok := <-d.ch:
		if !ok {
			d.ch = make(chan struct{})
		}
	default:
		break
	}

	if t.IsZero() {
		return nil
	}

	start := time.Now()
	if t.Before(start) {
		d.err = os.ErrDeadlineExceeded
		close(d.ch)
	} else {
		d.timer.Reset(t.Sub(start))
	}

	return nil
}

// NewDeadline returns a pointer to a new deadline expiring at time t
func NewDeadline(t time.Time) *Deadline {
	d := &Deadline{}
	// When first constructed, we want a timer that will never expire
	// Since there is no way create this, we make a timer that expires
	// far in the future (~290 years) and immediately cancel it.
	d.timer = time.AfterFunc(math.MaxInt64, d.timeout)
	if !d.timer.Stop() {
		<-d.timer.C
	}
	d.ch = make(chan struct{})
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
	case <-errChan:
		err = d.deadline.Err()
		return
	default:
		select {
		case <-errChan:
			err = d.deadline.Err()
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
	case <-errChan:
		err = d.deadline.Err()
		return
	default:
		select {
		case <-errChan:
			err = d.deadline.Err()
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
