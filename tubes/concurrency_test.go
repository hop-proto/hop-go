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

// TestReliablePublishesClosedBeforeSenderDrain verifies that late packet
// handlers reject new work while shutdown waits for the sender consumer.
func TestReliablePublishesClosedBeforeSenderDrain(t *testing.T) {
	log := logrus.WithField("test", t.Name())
	r := &Reliable{
		sender:     newSender(log),
		recvWindow: newReceiver(log),
		tubeState:  initiated,
		closed:     make(chan struct{}),
		sendDone:   make(chan struct{}),
		log:        log,
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
		sender:     newSender(log),
		recvWindow: newReceiver(log),
		tubeState:  created,
		closed:     make(chan struct{}),
		initRecv:   make(chan struct{}),
		initDone:   make(chan struct{}),
		sendDone:   make(chan struct{}),
		log:        log,
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
	r := &Reliable{
		sender:     newSender(log),
		recvWindow: newReceiver(log),
		sendQueue:  make(chan []byte, 1),
		tubeState:  created,
		closed:     make(chan struct{}),
		initRecv:   make(chan struct{}),
		initDone:   make(chan struct{}),
		sendDone:   make(chan struct{}),
		log:        log,
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

	r.sender.sendQueue <- &frame{data: []byte("started"), dataLength: 7}
	select {
	case <-r.sendQueue:
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
		sender:     newSender(log),
		recvWindow: newReceiver(log),
		tubeState:  initiated,
		closed:     make(chan struct{}),
		initDone:   make(chan struct{}),
		sendDone:   make(chan struct{}),
		log:        log,
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
	initiatedCh := make(chan struct{})
	close(initiatedCh)
	initiateDone := make(chan struct{})
	close(initiateDone)
	u := &Unreliable{
		sendQueue:    make(chan []byte, 2),
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

	dataFrame, err := fromBytes(<-u.sendQueue)
	assert.NilError(t, err)
	assert.Assert(t, !dataFrame.flags.FIN)

	finFrame, err := fromBytes(<-u.sendQueue)
	assert.NilError(t, err)
	assert.Assert(t, finFrame.flags.FIN)
}

// TestUnreliableInitiationGuardStartsSenderAfterResponse verifies that a
// response observed at the retransmit guard still starts the sender consumer.
func TestUnreliableInitiationGuardStartsSenderAfterResponse(t *testing.T) {
	u := &Unreliable{
		sendQueue:    make(chan []byte, 2),
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
	case got := <-u.sendQueue:
		assert.DeepEqual(t, got, []byte("started"))
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
	assert.Equal(t, len(u.recv.C), 0)
}
