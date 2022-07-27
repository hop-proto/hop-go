package common

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"gotest.tools/assert"
)

const numLoops = 1024
var ErrTest = errors.New("this is a test error")

var ErrTest = errors.New("this is a test error")

func TestFutureDeadline(t *testing.T) {
	deadline := NewDeadline(time.Time{})

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-deadline.Done()
		assert.ErrorType(t, deadline.Err(), os.ErrDeadlineExceeded)
	}()

	deadline.SetDeadline(time.Now().Add(time.Millisecond))
	wg.Wait()
}

func TestManyDeadlines(t *testing.T) {
	deadline := NewDeadline(time.Time{})

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func() {
			defer wg.Done()
			<-deadline.Done()
			assert.ErrorType(t, deadline.Err(), os.ErrDeadlineExceeded)
		}()
	}

	deadline.SetDeadline(time.Now().Add(time.Millisecond))
	wg.Wait()
}

func TestPastDeadline(t *testing.T) {
	deadline := NewDeadline(time.Time{})

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func() {
			defer wg.Done()
			<-deadline.Done()
			assert.ErrorType(t, deadline.Err(), os.ErrDeadlineExceeded)
		}()
	}

	deadline.SetDeadline(time.Now().Add(-time.Hour))
	wg.Wait()
}

func TestPresentDeadline(t *testing.T) {
	deadline := NewDeadline(time.Time{})

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func() {
			defer wg.Done()
			<-deadline.Done()
			assert.ErrorType(t, deadline.Err(), os.ErrDeadlineExceeded)
		}()
	}

	deadline.SetDeadline(time.Now())
	wg.Wait()
}

func TestCancel(t *testing.T) {
	deadline := NewDeadline(time.Time{})

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func() {
			defer wg.Done()
			<-deadline.Done()
			assert.ErrorType(t, deadline.Err(), ErrTest)
		}()
	}

	deadline.Cancel(ErrTest)
	wg.Wait()
}

func TestDoneOnTimedOut(t *testing.T) {
	deadline := NewDeadline(time.Time{})
	deadline.SetDeadline(time.Now().Add(-time.Hour))

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func() {
			defer wg.Done()
			<-deadline.Done()
			assert.ErrorType(t, deadline.Err(), os.ErrDeadlineExceeded)
		}()
	}

	wg.Wait()
}

func TestDoneOnCanceled(t *testing.T) {
	deadline := NewDeadline(time.Time{})
	deadline.Cancel(ErrTest)

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func() {
			defer wg.Done()
			<-deadline.Done()
			assert.ErrorType(t, deadline.Err(), ErrTest)
		}()
	}

	wg.Wait()
}

func TestDoubleCancel(t *testing.T) {
	deadline := NewDeadline(time.Now())
	deadline.Cancel(nil)
	deadline.Cancel(nil)
}

func TestUncancel(t *testing.T) {
	deadline := NewDeadline(time.Now())
	_, open := <-deadline.Done()
	assert.DeepEqual(t, open, false)

	deadline.SetDeadline(time.Now().Add(time.Hour))
	select {
	case <-deadline.Done():
		t.Error("Deadline should not have expired")
	default:
		break
	}
}

func TestDeadlineStress(t *testing.T) {
	deadline := NewDeadline(time.Now())
	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		for i := 0; i < 1000; i++ {
			deadline.SetDeadline(time.Now())
		}
		wg.Done()
	}()

	go func() {
		for i := 0; i < 1000; i++ {
			c := deadline.Done()
			<-c
		}
		wg.Done()
	}()

	wg.Wait()
}

func TestDeadlineRecv(t *testing.T) {
	ch := NewDeadlineChan[[]byte](numLoops)

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		ch.C <- []byte{77}
		go func() {
			defer wg.Done()
			val, err := ch.Recv()
			assert.NilError(t, err)
			assert.DeepEqual(t, val[0], byte(77))
		}()
	}

	wg.Wait()
}

func TestDeadlineRecvCancel(t *testing.T) {
	ch := NewDeadlineChan[[]byte](numLoops)

	ch.Cancel(ErrTest)

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func() {
			defer wg.Done()
			_, err := ch.Recv()
			assert.ErrorType(t, err, ErrTest)
		}()
	}

	wg.Wait()
}
func TestDeadlineSend(t *testing.T) {
	ch := NewDeadlineChan[[]byte](numLoops)

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func() {
			defer wg.Done()
			err := ch.Send([]byte{77})
			assert.NilError(t, err)
		}()
	}

	wg.Wait()
	ch.Close()
	for {
		val, err := ch.Recv()
		if err != nil {
			assert.ErrorType(t, err, io.EOF)
			break
		}
		assert.DeepEqual(t, val[0], byte(77))
	}
}

func TestDeadlineSendCancel(t *testing.T) {
	ch := NewDeadlineChan[[]byte](numLoops)

	ch.Cancel(ErrTest)

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func() {
			defer wg.Done()
			err := ch.Send([]byte{77})
			assert.ErrorType(t, err, ErrTest)
		}()
	}

	wg.Wait()
}
