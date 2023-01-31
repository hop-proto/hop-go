package tubes

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
	"hop.computer/hop/transport"
)

type muxerState int32

// a Muxer can be in one of three states
// muxerRunning indicates the muxer is able to create and accept new tubes
// muxerStopping indicates that Stop() has been called and the muxer is waiting on its Tubes to close. In this state, the muxer cannot create or accept new tubes.
// muxerStopped indicates that all tubes have been closed. In this state, the muxer cannot create or accept tubes.
const (
	muxerRunning  muxerState = iota
	muxerStopping muxerState = iota
	muxerStopped  muxerState = iota
)

// Tube interface is shared between Reliable and Unreliable Tubes
type Tube interface {
	net.Conn
	initiate(req bool)
	receiveInitiatePkt(*initiateFrame) error
	receive(*frame) error
	Type() TubeType
	GetID() byte
	IsReliable() bool
	WaitForClose()
	getLog() *logrus.Entry
}

// Muxer handles delivering and sending tube messages
type Muxer struct {
	tubeQueue chan Tube

	idParity byte

	m sync.Mutex
	// +checklocks:m
	reliableTubes map[byte]*Reliable
	// +checklocks:m
	unreliableTubes map[byte]*Unreliable

	// All hop tubes write raw bytes for a tube packet to this golang chan.
	sendQueue  chan []byte
	state      atomic.Value
	stopped    chan struct{}
	underlying transport.MsgConn
	timeout    time.Duration
	log        *logrus.Entry

	receiverErr chan error
	senderErr   chan error
	stopErr     error

	// This buffer is only used in m.readMsg
	readBuf []byte

	localKeepAliveTube  *Unreliable
	remoteKeepAliveTube *Unreliable
	localKeepAliveDone  chan struct{}
	remoteKeepAliveDone chan struct{}
}

// NewMuxer starts a new tube muxer
func NewMuxer(msgConn transport.MsgConn, timeout time.Duration, isServer bool, log *logrus.Entry) *Muxer {
	var idParity byte
	if isServer {
		idParity = 0
	} else {
		idParity = 1
	}
	state := atomic.Value{}
	mux := &Muxer{
		idParity:            idParity,
		reliableTubes:       make(map[byte]*Reliable),
		unreliableTubes:     make(map[byte]*Unreliable),
		tubeQueue:           make(chan Tube, 128),
		m:                   sync.Mutex{},
		sendQueue:           make(chan []byte),
		state:               state,
		stopped:             make(chan struct{}),
		underlying:          msgConn,
		timeout:             timeout,
		log:                 log,
		readBuf:             make([]byte, 65535),
		receiverErr:         make(chan error),
		senderErr:           make(chan error),
		localKeepAliveDone:  make(chan struct{}),
		remoteKeepAliveDone: make(chan struct{}),
	}

	mux.state.Store(muxerRunning)
	mux.start()

	return mux
}

// waits for tubes to close and then removes them so their IDs can be reused
func (m *Muxer) reapTube(t Tube) {
	t.WaitForClose()

	// This prevents tubes IDs from being reused while the remote peer is in the timeWait state.
	if _, ok := t.(*Reliable); ok && t.GetID()%2 == m.idParity {
		timer := time.NewTimer(timeWaitTime)
		select {
		case <-m.stopped:
			t.getLog().Debug("reaper stopped")
		case <-timer.C:
		}
	}

	t.getLog().Trace("reaping tube")

	m.m.Lock()
	defer m.m.Unlock()
	if t.IsReliable() {
		delete(m.reliableTubes, t.GetID())
	} else {
		delete(m.unreliableTubes, t.GetID())
	}
}

// +checklocks:m.m
func (m *Muxer) addTube(t Tube) {
	if t.IsReliable() {
		m.reliableTubes[t.GetID()] = t.(*Reliable)
	} else {
		m.unreliableTubes[t.GetID()] = t.(*Unreliable)
	}
	go m.reapTube(t)
}

func (m *Muxer) getTube(isReliable bool, tubeID byte) (Tube, bool) {
	m.m.Lock()
	defer m.m.Unlock()

	var t Tube
	var ok bool
	if isReliable {
		t, ok = m.reliableTubes[tubeID]
	} else {
		t, ok = m.unreliableTubes[tubeID]
	}
	return t, ok
}

// +checklocks:m.m
func (m *Muxer) pickTubeID(isReliable bool) (byte, error) {
	for guessInt := int(m.idParity); guessInt < 256; guessInt += 2 {
		guess := byte(guessInt)

		var ok bool
		if isReliable {
			_, ok = m.reliableTubes[guess]
		} else {
			_, ok = m.unreliableTubes[guess]
		}

		if !ok {
			m.log.WithField("tubeID", guess).Debug("picked new tube id")
			return guess, nil
		}
	}

	m.log.Warn("out of tube IDs")
	return 0, ErrOutOfTubes
}

// CreateReliableTube starts a new reliable tube
func (m *Muxer) CreateReliableTube(tType TubeType) (*Reliable, error) {
	m.m.Lock()
	defer m.m.Unlock()

	id, err := m.pickTubeID(true)
	if err != nil {
		return nil, err
	}
	tube, err := m.makeReliableTubeWithID(tType, id, true)
	if err == nil {
		m.log.Infof("Created Tube: %v", tube.GetID())
	}
	return tube, err
}

// +checklocks:m.m
func (m *Muxer) makeReliableTubeWithID(tType TubeType, tubeID byte, req bool) (*Reliable, error) {
	if m.state.Load() != muxerRunning {
		m.log.WithField("tube", tubeID).Debug("tried to make tube while muxer is stopping")
		return nil, ErrMuxerStopping
	}
	tubeLog := m.log.WithFields(logrus.Fields{
		"tube":     tubeID,
		"reliable": true,
		"tubeType": tType,
	})
	r := &Reliable{
		id:         tubeID,
		localAddr:  m.underlying.LocalAddr(),
		remoteAddr: m.underlying.RemoteAddr(),
		tubeState:  created,
		initRecv:   make(chan struct{}),
		initDone:   make(chan struct{}),
		sendDone:   make(chan struct{}),
		closed:     make(chan struct{}, 1),
		recvWindow: receiver{
			dataReady:   common.NewDeadlineChan[struct{}](1),
			buffer:      new(bytes.Buffer),
			fragments:   make(PriorityQueue, 0),
			windowSize:  windowSize,
			windowStart: 1,
			log:         tubeLog.WithField("receiver", ""),
		},
		sender: sender{
			ackNo:   1,
			frameNo: 1,
			buffer:  make([]byte, 0),
			// finSent defaults to false
			frameDataLengths: make(map[uint32]uint16),
			RTOTicker:        time.NewTicker(retransmitOffset),
			RTO:              retransmitOffset,
			windowSize:       windowSize,
			endRetransmit:    make(chan struct{}, 1),
			windowOpen:       make(chan struct{}, 1),
			sendQueue:        make(chan *frame),
			retransmitEnded:  make(chan struct{}, 1),
			log:              tubeLog.WithField("sender", ""),
		},
		sendQueue: m.sendQueue,
		tType:     tType,
		log:       tubeLog,
	}
	r.lastAckSent.Store(0)
	r.sender.closed.Store(true)
	m.addTube(r)
	r.recvWindow.init()
	go r.initiate(req)
	if !req {
		r.getLog().WithField("tube", r.GetID()).Debug("added tube to queue")
		m.tubeQueue <- r
	}
	return r, nil
}

// CreateUnreliableTube starts a new unreliable tube
func (m *Muxer) CreateUnreliableTube(tType TubeType) (*Unreliable, error) {
	m.m.Lock()
	defer m.m.Unlock()

	tubeID, err := m.pickTubeID(false)
	if err != nil {
		return nil, err
	}
	tube, err := m.makeUnreliableTubeWithID(tType, tubeID, true)
	if err == nil {
		m.log.Infof("Created Tube: %v", tube.GetID())
	}
	return tube, err
}

// req is true if the tube is a new request. False otherwise
// +checklocks:m.m
func (m *Muxer) makeUnreliableTubeWithID(tType TubeType, tubeID byte, req bool) (*Unreliable, error) {
	state := m.state.Load()
	if state != muxerRunning {
		m.log.WithField("tube", tubeID).Debug("tried to make tube while muxer is stopping")
		return nil, ErrMuxerStopping
	}
	tube := &Unreliable{
		tType:        tType,
		id:           tubeID,
		sendQueue:    m.sendQueue,
		localAddr:    m.underlying.LocalAddr(),
		remoteAddr:   m.underlying.RemoteAddr(),
		recv:         common.NewDeadlineChan[[]byte](maxBufferedPackets),
		send:         common.NewDeadlineChan[[]byte](maxBufferedPackets),
		state:        atomic.Value{},
		initiated:    make(chan struct{}),
		initiateDone: make(chan struct{}),
		senderDone:   make(chan struct{}),
		closed:       make(chan struct{}),
		log: m.log.WithFields(logrus.Fields{
			"tube":     tubeID,
			"reliable": false,
			"tubeType": tType,
		}),
	}
	m.addTube(tube)
	tube.state.Store(created)
	go tube.initiate(req)
	if !req {
		tube.getLog().WithField("tube", tube.GetID()).Debug("added tube to queue")
		m.tubeQueue <- tube
	}
	return tube, nil
}

// Accept blocks until a new tube is available or the muxer stops
func (m *Muxer) Accept() (Tube, error) {
	tube, ok := <-m.tubeQueue
	if !ok {
		return nil, ErrMuxerStopping
	}
	return tube, nil
}

func (m *Muxer) readMsg() (*frame, error) {
	_, err := m.underlying.ReadMsg(m.readBuf)
	if err != nil {
		return nil, err
	}

	// Set timeout
	if m.timeout != 0 {
		m.underlying.SetReadDeadline(time.Now().Add(m.timeout))
	}
	return fromBytes(m.readBuf)

}

func (m *Muxer) sender() {
	var err error
	for rawBytes := range m.sendQueue {
		err = m.underlying.WriteMsg(rawBytes)
		if err != nil {
			m.log.Warnf("error in muxer sender. stopping muxer: %s", err)
			// TODO(hosono) is it ok to stop the muxer here? Are the recoverable errors?
			go m.Stop()
			break
		}
	}

	// if we broke out of the loop, consume all packets so tubes can still close
	for range m.sendQueue {
	}

	m.log.WithField("error", err).Debug("muxer sender stopped")
	m.senderErr <- err
}

func (m *Muxer) start() {
	go m.sender()
	go m.receiver()
	m.startKeepAlive()
	m.state.Store(muxerRunning)
	m.log.Info("Muxer running!")
}

func (m *Muxer) startKeepAlive() {
	lt, err := m.CreateUnreliableTube(common.KeepAlive)
	m.localKeepAliveTube = lt
	if err != nil {
		// If we can't create this tube, the muxer might randomly time out
		// if it expects a keep alive and doesn't get it.
		// In that case, it's better to crash early
		m.log.WithField("error", err).Fatal("Failed to create keep alive tube")
	}
	m.localKeepAliveTube.log.Info("created keep alive tube")

	rt, err := m.Accept()
	// This case indicates that tubeQueue was closed by m.Stop()
	// In that case, there's no point in constructing keep alives
	if err != nil {
		close(m.localKeepAliveDone)
		close(m.remoteKeepAliveDone)
		return
	}
	m.remoteKeepAliveTube = rt.(*Unreliable)
	m.remoteKeepAliveTube.log.Info("received keep alive tube")

	go func() {
		buf := make([]byte, 1)
		ticker := time.NewTicker(retransmitOffset)
		for {
			<-ticker.C
			err := m.localKeepAliveTube.WriteMsg(buf)
			if err != nil {
				m.log.WithField("error", err).Info("Local keep alive ended")
				close(m.localKeepAliveDone)
				return
			}
		}
	}()

	go func() {
		for {
			buf := make([]byte, MaxFrameDataLength)
			_, err := m.remoteKeepAliveTube.Read(buf)
			if err != nil {
				m.log.WithField("error", err).Info("Remote keep alive ended")
				close(m.remoteKeepAliveDone)
				return
			}
		}
	}()
}

func (m *Muxer) receiver() {
	var err error

	// When start finishes, it sends its error on this channel.
	// m.Stop receives this error and passes it to the called.
	defer func() {
		// This case indicates that the muxer was stopped by m.Stop()
		if m.state.Load() == muxerStopped {
			m.log.WithFields(logrus.Fields{
				"state": m.state.Load(),
				"error": err,
			}).Info("muxer receiver stopping")
			err = nil
		} else if err != nil {
			m.log.Infof("Muxer receiver ended with error: %s", err)
			go m.Stop()
		} else {
			m.log.Debug("Muxer receiver ended with no error")
		}
		m.receiverErr <- err
	}()

	// Set initial timeout
	if m.timeout != 0 {
		m.underlying.SetReadDeadline(time.Now().Add(m.timeout))
	}
	for m.state.Load() != muxerStopped {
		frame, err := m.readMsg()
		if err != nil {
			return
		}
		var tube Tube
		tube, ok := m.getTube(frame.flags.REL, frame.tubeID)
		if !ok {
			m.log.WithField("tube", frame.tubeID).Info("tube not found")
			initFrame := fromInitiateBytes(frame.toBytes())

			// Handle requests for new tubes. We ignore errors when making a tube
			// because failing to create one tube should not shut down all tubes.
			if initFrame.flags.REQ {
				if initFrame.flags.REL {
					m.m.Lock()
					tube, _ = m.makeReliableTubeWithID(initFrame.tubeType, initFrame.tubeID, false)
					m.m.Unlock()
				} else {
					m.m.Lock()
					tube, _ = m.makeUnreliableTubeWithID(initFrame.tubeType, initFrame.tubeID, false)
					m.m.Unlock()
				}
			}
		}

		// Checking for tube != nil doesn't work because nil has a type
		// This means we have to check every possible type that tube could have
		if err == nil && tube != nil && tube != (*Reliable)(nil) && tube != (*Unreliable)(nil) {
			if frame.flags.REQ || frame.flags.RESP {
				initFrame := fromInitiateBytes(frame.toBytes())
				tube.receiveInitiatePkt(initFrame)
			} else {
				go tube.receive(frame)
			}
		}
	}
}

// WaitForStop blocks until the muxer is stopped and returns any error returned by start
func (m *Muxer) WaitForStop() error {
	<-m.stopped
	m.m.Lock()
	defer m.m.Unlock()
	return m.startErr
}

// Stop ensures all the muxer tubes are closed
func (m *Muxer) Stop() error {
	m.m.Lock()
	m.log.WithField("numTubes", len(m.reliableTubes)+len(m.unreliableTubes)).Info("Stopping muxer")

	var err error
	// Muxer.Stop() has already been called. Wait for it to finish
	if m.state.Load() != muxerRunning {
		m.m.Unlock()
		<-m.stopped

		m.m.Lock()
		defer m.m.Unlock()
		return m.stopErr
	}

	if m.localKeepAliveTube != nil {
		m.localKeepAliveTube.Close()
	}
	if m.remoteKeepAliveTube != nil {
		m.remoteKeepAliveTube.Close()
	}

	wg := sync.WaitGroup{}

	closeTube := func(t Tube) {
		wg.Add(1)
		go func(v Tube) { //parallelized closing tubes because other side may close them in a different order
			defer wg.Done()
			m.log.Info("Closing tube: ", v.GetID())
			err = v.Close()
			if err != nil && err != io.EOF {
				// Tried to close tube in bad state. Nothing to do
				m.log.Errorf("tube %d closed with error: %s", v.GetID(), err)
				return
			}
			v.WaitForClose()
		}(t)
	}

	for _, v := range m.reliableTubes {
		closeTube(v)
	}
	for _, v := range m.unreliableTubes {
		closeTube(v)
	}

	m.state.Store(muxerStopping)
	m.m.Unlock()

	// If tubes do not correctly close after some time, assume they never will and force them to close.
	time.AfterFunc(muxerTimeout, func() {
		if m.state.Load() == muxerStopped {
			return
		}
		m.m.Lock()
		for _, v := range m.reliableTubes {
			go func(r *Reliable) {
				r.l.Lock()
				defer r.l.Unlock()
				r.getLog().Error("Timed out. Forcing close")
				r.enterClosedState()
			}(v)
		}
		m.m.Unlock()
	})

	// Wait for all tubes to close
	wg.Wait()
	m.state.Store(muxerStopped)

	close(m.sendQueue)
	close(m.tubeQueue)
	<-m.localKeepAliveDone
	<-m.remoteKeepAliveDone

	m.underlying.Close()

	// Cache error for future calls to Stop
	recvErr := <-m.receiverErr
	sendErr := <-m.senderErr
	m.m.Lock()
	defer m.m.Unlock()
	if recvErr != nil {
		m.stopErr = recvErr
	} else if sendErr != nil {
		m.stopErr = sendErr
	} else {
		m.stopErr = nil
	}

	// This error indicates that the muxer got an ICMP Destination Unreachable packet.
	// This happens when the other side of the connetion has been closed, so we
	// can ignore it.
	if errors.Is(m.stopErr, syscall.ECONNREFUSED) {
		m.stopErr = nil
	}

	close(m.stopped)
	m.log.Info("Muxer.Stop() finished")
	return m.stopErr
}
