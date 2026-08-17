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

// DeadlineChan is a bounded channel with deadline and close cancellation.
//
// Close first rejects new senders and publishes cancellation, then waits for
// senders that registered before Close. In particular, Close never waits on a
// mutex held by a Send blocked on capacity. Values successfully sent before
// Close remain readable before Recv returns io.EOF. The raw channel is private
// so callers cannot race Close with an untracked send or close it themselves.
type DeadlineChan[T any] struct {
	deadline *Deadline
	closing  atomic.Bool

	// admissionMu protects the transition that rejects new senders. Send only
	// holds it while registering, never while waiting for channel capacity.
	admissionMu sync.Mutex
	senders     sync.WaitGroup
	closingDone chan struct{}
	sendersDone chan struct{}
	c           chan T
}

// Recv reads one value from the underlying channel.
// If the deadline is exceeded, Cancel is called, or Close is called,
// err will be set to a relevant error. Always check that err is nil before using b
func (d *DeadlineChan[T]) Recv() (b T, err error) {
	return d.recv()
}

func (d *DeadlineChan[T]) recv() (T, error) {
	var zero T
	// Return buffered data even if the channel is canceled
	select {
	case value := <-d.c:
		return value, nil
	default:
		break
	}

	if d.closing.Load() {
		// Close publishes cancellation before waiting for registered senders.
		// Wait for those senders to resolve, then recheck the buffer so a send
		// that linearized before Close is still observable.
		<-d.sendersDone
		select {
		case value := <-d.c:
			return value, nil
		default:
			return zero, io.EOF
		}
	}

	errChan := d.deadline.Done()
	select {
	case <-errChan:
		if d.closing.Load() {
			return d.RecvQueued()
		}
		return zero, d.deadline.Err()
	default:
		select {
		case <-errChan:
			if d.closing.Load() {
				return d.RecvQueued()
			}
			return zero, d.deadline.Err()
		case value := <-d.c:
			return value, nil
		}
	}
}

// RecvQueued receives values without observing operation deadlines. It is for
// an owning queue consumer that must keep draining values accepted before
// Close. Close still wakes it, after every registered sender has resolved.
func (d *DeadlineChan[T]) RecvQueued() (b T, err error) {
	for {
		select {
		case b = <-d.c:
			return b, nil
		default:
		}

		if d.closing.Load() {
			<-d.sendersDone
			select {
			case b = <-d.c:
				return b, nil
			default:
				return b, io.EOF
			}
		}

		select {
		case b = <-d.c:
			return b, nil
		case <-d.closingDone:
		}
	}
}

// Send writes one value to the underlying channel.
// If the deadline is exceeded, Cancel is called, or Close is called,
// err will not be nil.
func (d *DeadlineChan[T]) Send(b T) (err error) {
	d.admissionMu.Lock()
	if d.closing.Load() {
		d.admissionMu.Unlock()
		return io.EOF
	}
	d.senders.Add(1)
	d.admissionMu.Unlock()
	defer d.senders.Done()

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
		case d.c <- b:
			return
		}
	}
}

// TrySend attempts to send b without blocking. It returns false if the channel
// has no capacity, has been canceled, or is closing.
func (d *DeadlineChan[T]) TrySend(b T) bool {
	d.admissionMu.Lock()
	if d.closing.Load() {
		d.admissionMu.Unlock()
		return false
	}
	d.senders.Add(1)
	d.admissionMu.Unlock()
	defer d.senders.Done()

	errChan := d.deadline.Done()
	select {
	case <-errChan:
		return false
	default:
	}

	select {
	case <-errChan:
		return false
	case d.c <- b:
		return true
	default:
		return false
	}
}

// Len returns the number of buffered values. It is intended for diagnostics
// and tests; callers must not use it to coordinate concurrent operations.
func (d *DeadlineChan[T]) Len() int {
	return len(d.c)
}

// SetDeadline sets a time at which calls to Send and Recv will timeout
func (d *DeadlineChan[T]) SetDeadline(t time.Time) error {
	d.admissionMu.Lock()
	defer d.admissionMu.Unlock()
	if d.closing.Load() {
		return io.EOF
	}
	return d.deadline.SetDeadline(t)
}

// Cancel cancels pending calls to Send and Recv and causes them to return err
// TODO(hosono) when should Recv return buffered data
func (d *DeadlineChan[T]) Cancel(err error) error {
	d.admissionMu.Lock()
	defer d.admissionMu.Unlock()
	if d.closing.Load() {
		return io.EOF
	}
	d.deadline.Cancel(err)
	return nil
}

// Close cancels pending calls to Send and Recv. Those calls will return
// io.EOF rather than os.ErrDeadlineExceeded even after the deadline has expired
func (d *DeadlineChan[T]) Close() error {
	d.admissionMu.Lock()
	if d.closing.Load() {
		d.admissionMu.Unlock()
		<-d.sendersDone
		return io.EOF
	}
	d.closing.Store(true)
	close(d.closingDone)
	// Cancellation is published while no blocked Send holds admissionMu.
	d.deadline.Cancel(io.EOF)
	d.admissionMu.Unlock()

	d.senders.Wait()
	close(d.sendersDone)
	return nil
}

// NewDeadlineChan returns a pointer to a DeadlineChan with capacity of size
func NewDeadlineChan[T any](size int) *DeadlineChan[T] {
	return &DeadlineChan[T]{
		deadline:    NewDeadline(time.Time{}),
		closingDone: make(chan struct{}),
		sendersDone: make(chan struct{}),
		c:           make(chan T, size),
	}
}
