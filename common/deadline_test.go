package common

import (
	"os"
	"sync"
	"testing"
	"time"

	"gotest.tools/assert"
)

const numLoops = 1024

func TestFutureDeadline(t *testing.T) {
	deadline := NewDeadline(time.Time{})

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func () {
		defer wg.Done()
		err := <-deadline.Done()
		assert.ErrorType(t, err, os.ErrDeadlineExceeded)
	}()

	deadline.SetDeadline(time.Now().Add(time.Millisecond))
	wg.Wait()
}

func TestManyDeadlines(t *testing.T) {
	deadline := NewDeadline(time.Time{})

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func () {
			defer wg.Done()
			err := <-deadline.Done()
			assert.ErrorType(t, err, os.ErrDeadlineExceeded)
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
		go func () {
			defer wg.Done()
			err := <-deadline.Done()
			assert.ErrorType(t, err, os.ErrDeadlineExceeded)
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
		go func () {
			defer wg.Done()
			err := <-deadline.Done()
			assert.ErrorType(t, err, os.ErrDeadlineExceeded)
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
		go func () {
			defer wg.Done()
			err := <-deadline.Done()
			assert.ErrorType(t, err, ErrCanceled)
		}()
	}

	deadline.Cancel()
	wg.Wait()
}

func TestDoneOnTimedOut(t *testing.T) {
	deadline := NewDeadline(time.Time{})
	deadline.SetDeadline(time.Now().Add(-time.Hour))

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func () {
			defer wg.Done()
			err := <-deadline.Done()
			assert.ErrorType(t, err, os.ErrDeadlineExceeded)
		}()
	}

	wg.Wait()
}

func TestDoneOnCanceled(t *testing.T) {
	deadline := NewDeadline(time.Time{})
	deadline.Cancel()

	wg := sync.WaitGroup{}
	wg.Add(numLoops)
	for i := 0; i < numLoops; i++ {
		go func () {
			defer wg.Done()
			err := <-deadline.Done()
			assert.ErrorType(t, err, ErrCanceled)
		}()
	}

	wg.Wait()
}
