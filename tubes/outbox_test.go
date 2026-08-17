package tubes

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"gotest.tools/assert"
)

func waitForOutboxResult(t *testing.T, result <-chan error, message string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal(message)
		return nil
	}
}

// TestOutboxCancellationCoversEveryFrameClass verifies that shutdown can wake
// every kind of producer even when no Muxer sender is available to receive the
// handoff. Priority is admission metadata, not a separate cancellation domain.
func TestOutboxCancellationCoversEveryFrameClass(t *testing.T) {
	initRequest := (&initiateFrame{
		tubeID: 1,
		flags:  frameFlags{REQ: true, REL: true},
	}).toBytes()
	initResponse := (&initiateFrame{
		tubeID: 1,
		flags:  frameFlags{RESP: true, REL: true},
	}).toBytes()

	tests := []struct {
		name     string
		frame    []byte
		priority bool
	}{
		{name: "initiation request", frame: initRequest},
		{name: "initiation response", frame: initResponse},
		{name: "data", frame: (&frame{tubeID: 1, frameNo: 1, dataLength: 1, data: []byte{1}, flags: frameFlags{REL: true}}).toBytes()},
		{name: "RTO retransmission", frame: (&frame{tubeID: 1, frameNo: 1, dataLength: 1, data: []byte{1}, flags: frameFlags{REL: true, RTR: true}}).toBytes(), priority: true},
		{name: "priority retransmission", frame: (&frame{tubeID: 1, frameNo: 1, dataLength: 1, data: []byte{1}, flags: frameFlags{REL: true}}).toBytes(), priority: true},
		{name: "ACK", frame: (&frame{tubeID: 1, frameNo: 2, flags: frameFlags{REL: true, ACK: true}}).toBytes()},
		{name: "FIN", frame: (&frame{tubeID: 1, frameNo: 2, flags: frameFlags{REL: true, ACK: true, FIN: true}}).toBytes()},
		{name: "final FIN ACK", frame: (&frame{tubeID: 1, frameNo: 3, ackNo: 3, flags: frameFlags{REL: true, ACK: true}}).toBytes()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o := newOutbox()
			canceled := make(chan struct{})
			started := make(chan struct{})
			result := make(chan error, 1)
			go func() {
				close(started)
				result <- o.enqueue(outboundFrame{bytes: test.frame, priority: test.priority}, canceled)
			}()
			<-started

			select {
			case err := <-result:
				t.Fatalf("admission returned without a receiver or cancellation: %v", err)
			default:
			}
			close(canceled)
			assert.Assert(t, errors.Is(waitForOutboxResult(t, result, "canceled admission did not return"), io.EOF))
		})
	}
}

func TestOutboxAbortWakesNormalAndPriorityAdmissions(t *testing.T) {
	o := newOutbox()
	want := errors.New("transport write failed")
	start := make(chan struct{})
	started := make(chan struct{}, 2)
	results := make(chan error, 2)
	for _, priority := range []bool{false, true} {
		go func() {
			<-start
			started <- struct{}{}
			results <- o.enqueue(outboundFrame{bytes: []byte{1}, priority: priority}, nil)
		}()
	}
	close(start)
	<-started
	<-started
	o.abort(want)

	for range 2 {
		assert.Assert(t, errors.Is(waitForOutboxResult(t, results, "transport failure did not wake both admission priorities"), want))
	}
}

func TestOutboxShutdownCannotRaceSendOnClosedQueue(t *testing.T) {
	o := newOutbox()
	o.requestStop()

	const producers = 256
	var wg sync.WaitGroup
	errs := make(chan error, producers)
	wg.Add(producers)
	for i := range producers {
		go func() {
			defer wg.Done()
			errs <- o.enqueue(outboundFrame{bytes: []byte{byte(i)}, priority: i%2 == 0}, nil)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.Assert(t, errors.Is(err, ErrMuxerStopping))
	}

	// The owner never closes its data queues, even after both graceful stop and
	// abort are published. Repeated calls remain idempotent and panic-free.
	o.requestStop()
	o.abort(errors.New("late abort"))
}
