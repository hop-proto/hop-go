package tubes

import (
	"errors"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"

	"hop.computer/hop/common"
)

func newRecordingOutbox(t *testing.T) (*outbox, <-chan outboundFrame) {
	t.Helper()
	o := newOutbox()
	recorded := make(chan outboundFrame, 1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case raw := <-o.priority:
				recorded <- outboundFrame{bytes: raw, priority: true}
			case raw := <-o.normal:
				recorded <- outboundFrame{bytes: raw}
			case <-o.aborted:
				return
			case <-o.stop:
				return
			}
		}
	}()
	t.Cleanup(func() {
		o.requestStop()
		<-done
	})
	return o, recorded
}

// TestReliablePublishesClosedBeforeSenderDrain verifies that late packet
// handlers reject new work while shutdown waits for the sender consumer.
func TestReliablePublishesClosedBeforeSenderDrain(t *testing.T) {
	log := logrus.WithField("test", t.Name())
	r := &Reliable{
		sender:         newSender(log),
		recvWindow:     newReceiver(log),
		tubeState:      initiated,
		closed:         make(chan struct{}),
		closeRequested: make(chan struct{}),
		sendDone:       make(chan struct{}),
		log:            log,
	}
	r.l.Lock()
	r.sender.closed.Store(false)
	r.l.Unlock()

	enterDone := make(chan struct{})
	go func() {
		r.l.Lock()
		r.enterClosedState()
		r.l.Unlock()
		close(enterDone)
	}()

	deadline := time.Now().Add(time.Second)
	senderClosing := false
	for !senderClosing && time.Now().Before(deadline) {
		r.l.Lock()
		senderClosing = r.sender.closed.Load()
		r.l.Unlock()
		runtime.Gosched()
	}
	if !senderClosing {
		close(r.sendDone)
		<-enterDone
		t.Fatal("sender did not begin closing")
	}

	r.l.Lock()
	stateDuringDrain := r.tubeState
	r.l.Unlock()

	close(r.sendDone)
	select {
	case <-enterDone:
	case <-time.After(time.Second):
		t.Fatal("reliable close did not finish after sender drain")
	}

	assert.Equal(t, stateDuringDrain, closed)
}

// TestReliableOwnsSenderQueueClosure verifies that sender errors are reported
// upward instead of independently closing queues owned by the Reliable.
func TestReliableOwnsSenderQueueClosure(t *testing.T) {
	s := newSender(logrus.WithField("test", t.Name()))
	s.senderWindow.duplicatedAckCounter = 101

	_, err := s.recvAck(25)
	assert.Assert(t, errors.Is(err, errTooManyDuplicateACKs))
	assert.Assert(t, !s.closed.Load(), "sender closed queues outside the Reliable lifecycle")

	assert.NilError(t, s.Close())
}

// TestReliableForcedCloseStopsResponderInit verifies that shutdown wakes and
// joins a responder initiation producer that has not received its INIT frame.
func TestReliableForcedCloseStopsResponderInit(t *testing.T) {
	log := logrus.WithField("test", t.Name())
	r := &Reliable{
		sender:         newSender(log),
		recvWindow:     newReceiver(log),
		tubeState:      created,
		closed:         make(chan struct{}),
		closeRequested: make(chan struct{}),
		initRecv:       make(chan struct{}),
		initDone:       make(chan struct{}),
		sendDone:       make(chan struct{}),
		log:            log,
	}
	r.l.Lock()
	r.sender.closed.Store(true)
	r.l.Unlock()
	go r.initiate(false)

	r.l.Lock()
	r.enterClosedState()
	r.l.Unlock()

	select {
	case <-r.initDone:
	case <-time.After(time.Second):
		t.Fatal("forced close did not stop responder initiation")
	}
	r.WaitForClose()
}

// TestReliableInitiationGuardStartsSenderAfterResponse verifies that a response
// winning concurrently with a retransmit check is success, not cancellation.
func TestReliableInitiationGuardStartsSenderAfterResponse(t *testing.T) {
	log := logrus.WithField("test", t.Name())
	outbound, recorded := newRecordingOutbox(t)
	r := &Reliable{
		sender:         newSender(log),
		recvWindow:     newReceiver(log),
		outbound:       outbound,
		tubeState:      created,
		closed:         make(chan struct{}),
		closeRequested: make(chan struct{}),
		initRecv:       make(chan struct{}),
		initDone:       make(chan struct{}),
		sendDone:       make(chan struct{}),
		log:            log,
	}
	r.l.Lock()
	r.sender.closed.Store(true)
	r.l.Unlock()

	assert.NilError(t, r.receiveInitiatePkt(&initiateFrame{
		flags: frameFlags{RESP: true, REL: true},
	}))
	r.initiate(true)

	r.l.Lock()
	senderStarted := !r.sender.closed.Load()
	r.l.Unlock()
	if !senderStarted {
		t.Fatal("successful initiation did not enable the reliable sender")
	}

	_, err := r.Write([]byte("started"))
	assert.NilError(t, err)
	select {
	case <-recorded:
	case <-time.After(time.Second):
		t.Fatal("reliable sender did not hand queued frame to the muxer")
	}

	r.l.Lock()
	r.enterClosedState()
	r.l.Unlock()
	r.WaitForClose()
}

// TestReliableForcedCloseBeforeSenderStart verifies that an initiated state does
// not imply a sender exists until startup enables it under the lifecycle lock.
func TestReliableForcedCloseBeforeSenderStart(t *testing.T) {
	log := logrus.WithField("test", t.Name())
	r := &Reliable{
		sender:         newSender(log),
		recvWindow:     newReceiver(log),
		tubeState:      initiated,
		closed:         make(chan struct{}),
		closeRequested: make(chan struct{}),
		initDone:       make(chan struct{}),
		sendDone:       make(chan struct{}),
		log:            log,
	}
	r.l.Lock()
	r.sender.closed.Store(true)
	r.enterClosedState()
	r.l.Unlock()
	close(r.initDone)

	r.WaitForClose()
}

// TestUnreliableCloseQueuesFINLast verifies that Close stops writers before
// placing the FIN behind every message already accepted into the local queue.
func TestUnreliableCloseQueuesFINLast(t *testing.T) {
	outbound, recorded := newRecordingOutbox(t)
	initiatedCh := make(chan struct{})
	close(initiatedCh)
	initiateDone := make(chan struct{})
	close(initiateDone)
	u := &Unreliable{
		outbound:     outbound,
		initiated:    initiatedCh,
		initiateDone: initiateDone,
		stopInitiate: make(chan struct{}),
		senderDone:   make(chan struct{}),
		closed:       make(chan struct{}),
		recv:         common.NewDeadlineChan[[]byte](1),
		send:         common.NewDeadlineChan[[]byte](1),
		log:          logrus.WithField("test", t.Name()),
	}
	u.state.Store(initiated)
	go u.sender()

	assert.NilError(t, u.WriteMsg([]byte("before close")))
	assert.NilError(t, u.Close())
	assert.Assert(t, errors.Is(u.WriteMsg([]byte("after close")), io.EOF))

	dataFrame, err := fromBytes((<-recorded).bytes)
	assert.NilError(t, err)
	assert.Assert(t, !dataFrame.flags.FIN)

	finFrame, err := fromBytes((<-recorded).bytes)
	assert.NilError(t, err)
	assert.Assert(t, finFrame.flags.FIN)
}

// TestUnreliableInitiationGuardStartsSenderAfterResponse verifies that a
// response observed at the retransmit guard still starts the sender consumer.
func TestUnreliableInitiationGuardStartsSenderAfterResponse(t *testing.T) {
	outbound, recorded := newRecordingOutbox(t)
	u := &Unreliable{
		outbound:     outbound,
		initiated:    make(chan struct{}),
		initiateDone: make(chan struct{}),
		stopInitiate: make(chan struct{}),
		senderDone:   make(chan struct{}),
		closed:       make(chan struct{}),
		recv:         common.NewDeadlineChan[[]byte](1),
		send:         common.NewDeadlineChan[[]byte](2),
		log:          logrus.WithField("test", t.Name()),
	}
	u.state.Store(created)

	assert.NilError(t, u.receiveInitiatePkt(&initiateFrame{
		flags: frameFlags{RESP: true},
	}))
	u.initiate(true)

	select {
	case <-u.senderDone:
		t.Fatal("successful initiation was treated as sender cancellation")
	default:
	}

	assert.NilError(t, u.send.Send([]byte("started")))
	select {
	case got := <-recorded:
		assert.DeepEqual(t, got.bytes, []byte("started"))
	case <-time.After(time.Second):
		t.Fatal("unreliable sender did not hand queued message to the muxer")
	}

	assert.NilError(t, u.Close())
}

// TestUnreliableRejectsReceiveAfterClose verifies that the receive producer
// cannot enqueue new buffered data after lifecycle shutdown is published.
func TestUnreliableRejectsReceiveAfterClose(t *testing.T) {
	u := &Unreliable{
		recv: common.NewDeadlineChan[[]byte](1),
	}
	u.state.Store(closed)

	err := u.receive(&frame{data: []byte("late"), dataLength: 4})
	assert.Assert(t, errors.Is(err, ErrBadTubeState))
	assert.Equal(t, u.recv.Len(), 0)
}

// TestUnreliableResponderWaitsForInitiationRequest forces the responder
// initiation goroutine to run before the Muxer dispatches the peer's request.
// The sender must wait for that event instead of exiting permanently.
func TestUnreliableResponderWaitsForInitiationRequest(t *testing.T) {
	outbound, recorded := newRecordingOutbox(t)
	u := &Unreliable{
		outbound:     outbound,
		initiated:    make(chan struct{}),
		initiateDone: make(chan struct{}),
		stopInitiate: make(chan struct{}),
		senderDone:   make(chan struct{}),
		closed:       make(chan struct{}),
		recv:         common.NewDeadlineChan[[]byte](1),
		send:         common.NewDeadlineChan[[]byte](1),
		log:          logrus.WithField("test", t.Name()),
	}
	u.state.Store(created)
	go u.initiate(false)
	runtime.Gosched()

	select {
	case <-u.initiateDone:
		t.Fatal("responder initiation exited before receiving the request")
	default:
	}

	assert.NilError(t, u.receiveInitiatePkt(&initiateFrame{flags: frameFlags{REQ: true}}))
	select {
	case admitted := <-recorded:
		response := fromInitiateBytes(admitted.bytes)
		assert.Assert(t, response.flags.RESP)
	case <-time.After(time.Second):
		t.Fatal("responder did not admit its initiation response")
	}
	select {
	case <-u.initiateDone:
	case <-time.After(time.Second):
		t.Fatal("responder initiation did not complete after the request")
	}

	assert.NilError(t, u.WriteMsg([]byte("sender started")))
	select {
	case admitted := <-recorded:
		pkt, err := fromBytes(admitted.bytes)
		assert.NilError(t, err)
		assert.DeepEqual(t, pkt.data, []byte("sender started"))
	case <-time.After(time.Second):
		t.Fatal("responder sender did not run after initiation")
	}
	assert.NilError(t, u.Close())
}

func TestReliableCloseCancelsBlockedInitiationAdmission(t *testing.T) {
	log := logrus.WithField("test", t.Name())
	r := &Reliable{
		sender:         newSender(log),
		recvWindow:     newReceiver(log),
		outbound:       newOutbox(),
		tubeState:      created,
		closed:         make(chan struct{}),
		closeRequested: make(chan struct{}),
		initRecv:       make(chan struct{}),
		initDone:       make(chan struct{}),
		sendDone:       make(chan struct{}),
		log:            log,
	}
	r.sender.closed.Store(true)
	go r.initiate(true)
	runtime.Gosched()

	result := make(chan error, 1)
	go func() {
		result <- r.Close()
	}()
	select {
	case err := <-result:
		assert.Assert(t, errors.Is(err, ErrBadTubeState))
	case <-time.After(time.Second):
		t.Fatal("Reliable.Close did not cancel blocked initiation admission")
	}
	r.WaitForClose()
}

func TestUnreliableCloseCancelsBlockedInitiationAdmission(t *testing.T) {
	u := &Unreliable{
		outbound:     newOutbox(),
		initiated:    make(chan struct{}),
		initiateDone: make(chan struct{}),
		stopInitiate: make(chan struct{}),
		senderDone:   make(chan struct{}),
		closed:       make(chan struct{}),
		recv:         common.NewDeadlineChan[[]byte](1),
		send:         common.NewDeadlineChan[[]byte](1),
		log:          logrus.WithField("test", t.Name()),
	}
	u.state.Store(created)
	go u.initiate(true)
	runtime.Gosched()

	result := make(chan error, 1)
	go func() {
		result <- u.Close()
	}()
	select {
	case err := <-result:
		assert.NilError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Unreliable.Close did not cancel blocked initiation admission")
	}
}

func TestUnreliableCloseCancelsWriterUnderBackpressure(t *testing.T) {
	outbound := newOutbox()
	initiatedCh := make(chan struct{})
	close(initiatedCh)
	initiateDone := make(chan struct{})
	close(initiateDone)
	u := &Unreliable{
		outbound:     outbound,
		initiated:    initiatedCh,
		initiateDone: initiateDone,
		stopInitiate: make(chan struct{}),
		senderDone:   make(chan struct{}),
		closed:       make(chan struct{}),
		recv:         common.NewDeadlineChan[[]byte](1),
		send:         common.NewDeadlineChan[[]byte](1),
		log:          logrus.WithField("test", t.Name()),
	}
	u.state.Store(initiated)
	go u.sender()

	assert.NilError(t, u.WriteMsg([]byte("blocked at outbox")))
	deadline := time.Now().Add(time.Second)
	for u.send.Len() != 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	assert.Equal(t, u.send.Len(), 0, "sender did not reach blocked outbox admission")
	assert.NilError(t, u.WriteMsg([]byte("fills local queue")))

	writeStarted := make(chan struct{})
	writeResult := make(chan error, 1)
	go func() {
		close(writeStarted)
		writeResult <- u.WriteMsg([]byte("blocked on local queue"))
	}()
	<-writeStarted
	runtime.Gosched()

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- u.Close()
	}()
	select {
	case err := <-writeResult:
		assert.Assert(t, errors.Is(err, io.EOF))
	case <-time.After(time.Second):
		t.Fatal("Close could not cancel a writer blocked by local backpressure")
	}

	// Close is still correctly waiting for its sender; transport failure now
	// releases the blocked Muxer admission and completes the drain.
	outbound.abort(errors.New("test transport failure"))
	select {
	case err := <-closeResult:
		assert.NilError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Close did not complete after outbound failure")
	}
}

func TestUnreliableConcurrentClose(t *testing.T) {
	outbound, _ := newRecordingOutbox(t)
	initiatedCh := make(chan struct{})
	close(initiatedCh)
	initiateDone := make(chan struct{})
	close(initiateDone)
	u := &Unreliable{
		outbound:     outbound,
		initiated:    initiatedCh,
		initiateDone: initiateDone,
		stopInitiate: make(chan struct{}),
		senderDone:   make(chan struct{}),
		closed:       make(chan struct{}),
		recv:         common.NewDeadlineChan[[]byte](1),
		send:         common.NewDeadlineChan[[]byte](1),
		log:          logrus.WithField("test", t.Name()),
	}
	u.state.Store(initiated)
	go u.sender()

	const closers = 32
	start := make(chan struct{})
	results := make(chan error, closers)
	for range closers {
		go func() {
			<-start
			results <- u.Close()
		}()
	}
	close(start)

	nilResults := 0
	for range closers {
		select {
		case err := <-results:
			if err == nil {
				nilResults++
			} else {
				assert.Assert(t, errors.Is(err, io.EOF))
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent Close did not return")
		}
	}
	assert.Equal(t, nilResults, 1)
}
