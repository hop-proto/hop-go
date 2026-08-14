package tubes

import (
	"errors"
	"io"
	"sync"
)

// outboundFrame is one tube-to-Muxer admission request. Only the Muxer sender
// receives from the two outbox queues; producers cannot access or close them.
type outboundFrame struct {
	bytes    []byte
	priority bool
}

// outbox owns cancellable admission to the Muxer sender. The data queues are
// deliberately never closed: stop and abort are the only shutdown signals, so
// a producer can never race a send with queue closure.
type outbox struct {
	normal   chan []byte
	priority chan []byte

	stop      chan struct{}
	aborted   chan struct{}
	stopOnce  sync.Once
	abortOnce sync.Once

	errMu sync.Mutex
	// +checklocks:errMu
	err error
}

func newOutbox() *outbox {
	return &outbox{
		normal:   make(chan []byte),
		priority: make(chan []byte),
		stop:     make(chan struct{}),
		aborted:  make(chan struct{}),
	}
}

// enqueue blocks until the Muxer sender admits frame or either the producer or
// Muxer is canceled. No caller may hold a lifecycle lock while calling enqueue.
func (o *outbox) enqueue(frame outboundFrame, producerCanceled <-chan struct{}) error {
	queue := o.normal
	if frame.priority {
		queue = o.priority
	}

	select {
	case <-o.aborted:
		return o.abortErr()
	case <-producerCanceled:
		return o.cancellationErr(io.EOF)
	case <-o.stop:
		return o.cancellationErr(ErrMuxerStopping)
	default:
	}

	select {
	case <-o.aborted:
		return o.abortErr()
	case <-producerCanceled:
		return o.cancellationErr(io.EOF)
	case <-o.stop:
		return o.cancellationErr(ErrMuxerStopping)
	case queue <- frame.bytes:
		return nil
	}
}

// cancellationErr gives an already-published transport failure precedence over
// graceful or producer cancellation. abort always happens before failure-driven
// Stop begins, so all blocked priorities observe the causal error.
func (o *outbox) cancellationErr(fallback error) error {
	select {
	case <-o.aborted:
		return o.abortErr()
	default:
		return fallback
	}
}

// requestStop asks the sender to exit after all tube producers have completed.
// Stop is closed by the Muxer shutdown owner and is never used to drain queues.
func (o *outbox) requestStop() {
	o.stopOnce.Do(func() {
		close(o.stop)
	})
}

// abort publishes failure without waiting for either queue. It wakes producers
// blocked on normal and priority admission at the same instant.
func (o *outbox) abort(err error) {
	if err == nil {
		err = ErrMuxerStopping
	}
	o.abortOnce.Do(func() {
		o.errMu.Lock()
		o.err = err
		o.errMu.Unlock()
		close(o.aborted)
	})
}

func (o *outbox) abortErr() error {
	o.errMu.Lock()
	defer o.errMu.Unlock()
	if o.err == nil {
		return errors.New("muxer outbound path aborted")
	}
	return o.err
}
