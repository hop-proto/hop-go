package common

import (
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type AtomicBool int32

func (b *AtomicBool) IsSet() bool { return atomic.LoadInt32((*int32)(b)) != 0 }
func (b *AtomicBool) SetTrue()    { atomic.StoreInt32((*int32)(b), 1) }
func (b *AtomicBool) SetFalse()   { atomic.StoreInt32((*int32)(b), 0) }

type AtomicTimeout int64

func (t *AtomicTimeout) Set(d time.Duration) {
	atomic.StoreInt64((*int64)(t), int64(d))
}

func (t *AtomicTimeout) Get() time.Duration {
	return time.Duration(atomic.LoadInt64((*int64)(t)))
}

type Deadline struct {
	chanLock	sync.Mutex
	// +checklocks:chanLock
	chans 		[]chan error

	timerLock	sync.Mutex
	// +checklocks:timerLock
	timer 		*time.Timer
	deadline 	time.Time

	active		AtomicBool

	// +checklocks:chanLock
	err 		error
}

func (d *Deadline) Done() chan error {
	d.chanLock.Lock()
	defer d.chanLock.Unlock()
	ch := make(chan error, 1)
	if !d.active.IsSet() {
		ch <- d.err
		close(ch)
	} else {
		d.chans = append(d.chans, ch)
	}
	return ch
}

func (d *Deadline) Cancel(err error) {
	d.chanLock.Lock()
	defer d.chanLock.Unlock()

	d.active.SetFalse()
	d.err = err

	for _, ch := range(d.chans) {
		ch <- err
		close(ch)
	}

	d.chans = nil
}

func (d *Deadline) timeout() {
	d.Cancel(os.ErrDeadlineExceeded)
}

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
		d.active.SetTrue()
		return nil
	}

	start := time.Now()
	if t.Before(start) {
		d.timeout()
	} else {
		d.active.SetTrue()
		d.timer.Reset(t.Sub(start))
	}

	return nil
}

func NewDeadline(t time.Time) *Deadline {
	d := &Deadline{}
	d.timer = time.AfterFunc(time.Hour, d.timeout)
	if !d.timer.Stop() {
		<-d.timer.C
	}
	d.active.SetTrue()
	d.SetDeadline(t)
	return d
}
