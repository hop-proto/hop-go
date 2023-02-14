package tubes

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
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

// Party indicates if a Muxer is an Intiator or a Responder
type Party bool

// There are only two types of Party
const (
	Initator  Party = false
	Responder Party = true
)

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

	senderErr chan error
	sendErr   error

	receiverErr chan error
	recvErr     error

	// This buffer is only used in m.readMsg
	readBuf []byte

	keepAliveTubeChan chan *Unreliable
	sendKeepAliveDone chan struct{}
	recvKeepAliveDone chan struct{}
}

// NewMuxer starts a new tube muxer running over the the specified msgConn.
// The newly created muxer will close the msgConn when Muxer.Stop() is called.
//
// timeout specifies how long the muxer will wait before timing out all operations
//
// isServer controls whether the muxer will create even or odd numbered tubes.
// When two muxers are connected, one must be creates with isServer set to true
// and the other must have isServer set to false. The server will create even
// numbered tubes. The client will create odd numbered tubes.
//
// log specifies the logging context for this muxer. All log messages from this
// muxer and the tubes it creates will use this logging context.
func NewMuxer(msgConn transport.MsgConn, timeout time.Duration, party Party, log *logrus.Entry) *Muxer {
	var idParity byte
	if party == Responder {
		idParity = 0
	} else {
		idParity = 1
	}
	mux := &Muxer{
		idParity:          idParity,
		reliableTubes:     make(map[byte]*Reliable),
		unreliableTubes:   make(map[byte]*Unreliable),
		tubeQueue:         make(chan Tube, 128),
		m:                 sync.Mutex{},
		sendQueue:         make(chan []byte),
		state:             atomic.Value{},
		stopped:           make(chan struct{}),
		underlying:        msgConn,
		timeout:           timeout,
		log:               log,
		readBuf:           make([]byte, 65535),
		receiverErr:       make(chan error),
		senderErr:         make(chan error),
		keepAliveTubeChan: make(chan *Unreliable, 1),
		sendKeepAliveDone: make(chan struct{}),
		recvKeepAliveDone: make(chan struct{}),
	}

	mux.state.Store(muxerRunning)
	mux.start()

	return mux
}

// waits for tubes to close and then removes them so their IDs can be reused
// reapTube is called in a goroutine whenever a tube is created or accepted.
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

// addTube adds a tube to the relevant map for later lookup.
// It automatically adds Reliable and Unreliable tubes to their respective maps.
// +checklocks:m.m
func (m *Muxer) addTube(t Tube) {
	if t.IsReliable() {
		m.reliableTubes[t.GetID()] = t.(*Reliable)
	} else {
		m.unreliableTubes[t.GetID()] = t.(*Unreliable)
	}
	go m.reapTube(t)
}

// getTube retrieves a tube from the muxer's maps. isReliable indicates
// whether the method retrieves a Reliable or an Unreliable tube.
// isReliable must be specified since tubes are identified by the tuple of
// tubeID and reliability. In other words, there can be both a reliable
// tube 17 and an unreliable tube 17.
//
// If no tube exists with the specified tubeID and reliablility
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

// pickTubeID performs a linear search through the muxer's map of tubes
// in order to find the next open tube ID. isReliable indicates whether
// this method will search through the map of Reliable or Unreliable tubes.
// If no tube IDs are available, this method returns ErrOutOfTubes.
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
			m.log.WithField("tubeID", guess).Trace("picked new tube id")
			return guess, nil
		}
	}
	return 0, ErrOutOfTubes
}

// CreateReliableTube starts a new reliable tube. If this method returns with
// a nil error, the tube it has created is ready to use. If the error is not nil,
// then the tube returned by this method will be nil
func (m *Muxer) CreateReliableTube(tType TubeType) (*Reliable, error) {
	m.m.Lock()
	defer m.m.Unlock()

	id, err := m.pickTubeID(true)
	if err != nil {
		return nil, err
	}
	tube, err := m.makeReliableTubeWithID(tType, id, true)
	if err != nil {
		return nil, err
	}
	m.log.Infof("Created Tube: %v", tube.GetID())
	return tube, err
}

// makeReliableTubeWithID populates the struct for a reliable tube and calls its initiate method.
// req is true if the tube is a new request and false if the tube responding to a request by the remote muxer.
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
		r.log.Debug("added tube to queue")
		m.tubeQueue <- r
	}
	return r, nil
}

// CreateUnreliableTube starts a new unreliable tube. If this method returns
// with a nil error, the created tube is ready for use. If it returns with an
// error, then the tube it returns will be nil.
func (m *Muxer) CreateUnreliableTube(tType TubeType) (*Unreliable, error) {
	m.m.Lock()
	defer m.m.Unlock()

	tubeID, err := m.pickTubeID(false)
	if err != nil {
		return nil, err
	}
	tube, err := m.makeUnreliableTubeWithID(tType, tubeID, true)
	if err != nil {
		return nil, err
	}
	m.log.Infof("Created Tube: %v", tube.GetID())
	return tube, err
}

// makeUnreliableTubeWithID populates the struct for an unreliable tube and calls its initiate method.
// req is true if the tube is a new request and false if the tube responding to a request by the remote muxer.
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

	// Check for received keep alive tubes. Keep alive tubes always have id 0
	if tube.id == 0 {
		m.keepAliveTubeChan <- tube
		return nil, errGotKeepAlive
	}

	if !req {
		tube.log.Debug("added tube to queue")
		m.tubeQueue <- tube
	}
	return tube, nil
}

// Accept blocks until a new tube is available or the muxer stops
// If the muxer stops, Accept will return a nil Tube and ErrMuxerStopping.
// Otherwise, it will return a valid tube that is ready for use.
func (m *Muxer) Accept() (Tube, error) {
	tube, ok := <-m.tubeQueue
	if !ok {
		return nil, ErrMuxerStopping
	}
	return tube, nil
}

// readMsg reads a new packet from the underlying MsgConn. It then sets the timeout
// so that future calls to readMsg will timeout appropriately.
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

// sender reads data from the muxer's sendQueue and writes it to the
// underlying MsgConn. If an error occurs while sending data, sender will call
// m.Stop in a new goroutine and the error will be reported by m.Stop
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

// start begins the goroutines that make the muxer work. Specifically,
// it starts the sender, the receiver, and the keep alive tubes.
func (m *Muxer) start() {
	go m.sender()
	go m.receiver()

	// lock needed to call makeUnreliableTubeWithID
	m.m.Lock()
	defer m.m.Unlock()

	// Create the server opens the keep alive tube, which will always have ID 0
	if m.idParity == 0 {
		// Tube ID 0 is reserved for keep alives
		_, err := m.makeUnreliableTubeWithID(common.KeepAlive, 0, true)
		if err != errGotKeepAlive {
			// If we can't create this tube, the muxer might randomly time out
			// if it expects a keep alive and doesn't get it.
			// In that case, it's better to crash early
			m.log.WithField("error", err).Fatal("Failed to create keep alive tube")
		}
		m.log.Info("created keep alive tube")
	}

	go m.startKeepAlive()
	m.log.Info("Muxer running!")
}

// startKeepAlive beings the goroutines that handle keep alive messages.
// startKeepAlive blocks until the keep alive tube is sent on m.keepAliveTubeChan.
// Ones it receives a keep alive tube, this method spawns two goroutines:
// One for sending keep alives and one for receiving them. The sending goroutine
// sends 3 keep alive messages every timeout interval. The receiving goroutine
// reads and discards every keep alive message sent by the remote muxer.
// The sending and receiving goroutines exit if any errors occur in the
// keep alive tube. They then close the channels m.sendKeepAliveDone and
// m.recvKeepAliveDone respectively.
func (m *Muxer) startKeepAlive() {
	tube := <-m.keepAliveTubeChan

	// a nil channel is sent by m.Stop to finish this goroutine
	if tube == nil {
		close(m.sendKeepAliveDone)
		close(m.recvKeepAliveDone)
		return
	}

	// This goroutine sends 3 keep alives per timeout
	go func() {
		defer close(m.sendKeepAliveDone)
		buf := make([]byte, 1)

		keepAliveTime := m.timeout / 3
		if keepAliveTime == 0 {
			keepAliveTime = 10 * retransmitOffset
		}
		ticker := time.NewTicker(keepAliveTime)
		for {
			<-ticker.C
			if tube == nil {
				m.log.Info("haven't receive keep alive tube yet")
				continue
			}
			err := tube.WriteMsg(buf)
			if err != nil {
				m.log.WithField("error", err).Info("Keep alive sender ended")
				return
			}
			m.log.Debug("send keep alive")
		}
	}()

	// This goroutine reads keep alives
	go func() {
		defer close(m.recvKeepAliveDone)
		buf := make([]byte, 1)
		for {
			_, err := tube.Read(buf)
			if err != nil {
				m.log.WithField("error", err).Info("Keep alive receiver ended")
				return
			}
			m.log.Debug("got keep alive")
		}
	}()
}

// receiver reads packet from the underlying MsgConn and forwards them to the relevant
// tubes. If it gets a REQ packet requesting a new tube, it creates that tube.
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

// Stop ensures all the muxer tubes are closed. Calls to Stop are idempotent.
// If a call to Stop is make while another call to stop is ongoing, the second
// call with block until the first call has finish. Stop returns two errors:
// the first error is any error returned by the muxer sender and the second
// any error returned by the muxer receiver.
func (m *Muxer) Stop() (sendErr error, recvErr error) {
	m.m.Lock()
	m.log.WithField("numTubes", len(m.reliableTubes)+len(m.unreliableTubes)).Info("Stopping muxer")

	// Muxer.Stop() has already been called. Wait for it to finish
	if m.state.Load() != muxerRunning {
		m.m.Unlock()
		<-m.stopped

		m.m.Lock()
		defer m.m.Unlock()
		return m.sendErr, m.recvErr
	}

	wg := sync.WaitGroup{}

	closeTube := func(t Tube) {
		wg.Add(1)
		go func(v Tube) { //parallelized closing tubes because other side may close them in a different order
			defer wg.Done()
			v.getLog().Info("Closing tube: ", v.GetID())
			err := v.Close()
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

	// This prevents startKeepAlive from blocking indefinitely waiting for a tube that isn't coming
	select {
	case m.keepAliveTubeChan <- nil:
	default:
	}

	close(m.sendQueue)
	close(m.tubeQueue)
	<-m.recvKeepAliveDone
	<-m.sendKeepAliveDone

	m.underlying.Close()

	// Cache error for future calls to Stop
	m.recvErr = <-m.receiverErr
	m.sendErr = <-m.senderErr
	m.m.Lock()
	defer m.m.Unlock()

	//// This error indicates that the muxer got an ICMP Destination Unreachable packet.
	//// This happens when the other side of the connetion has been closed, so we
	//// can ignore it.
	//if errors.Is(m.stopErr, syscall.ECONNREFUSED) {
	//m.stopErr = nil
	//}

	close(m.stopped)
	m.log.Info("Muxer.Stop() finished")
	return m.sendErr, m.recvErr
}
