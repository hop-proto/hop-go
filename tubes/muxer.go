package tubes

import (
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

	senderErr chan error
	sendErr   error

	receiverErr chan error
	recvErr     error

	// This buffer is only used in m.readMsg
	readBuf []byte
}

// A Config is used to configure a muxer client or server. After one has been
// passed to a Muxer function, it must not be modified. A Config may be reused;
// the tubes package does not modify it.
type Config struct {
	Timeout time.Duration
	Log     *logrus.Entry
}

// Client returns a new Muxer configured as a client.
func Client(msgConn transport.MsgConn, config *Config) *Muxer {
	return newMuxer(msgConn, config.Timeout, false, config.Log)
}

// Server returns a new Muxer configured as a server.
func Server(msgConn transport.MsgConn, config *Config) *Muxer {
	return newMuxer(msgConn, config.Timeout, true, config.Log)
}

// newMuxer starts a new tube muxer running over the the specified msgConn.
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
func newMuxer(msgConn transport.MsgConn, timeout time.Duration, isServer bool, log *logrus.Entry) *Muxer {
	var idParity byte
	if isServer {
		idParity = 0
	} else {
		idParity = 1
	}
	state := atomic.Value{}
	mux := &Muxer{
		idParity:        idParity,
		reliableTubes:   make(map[byte]*Reliable),
		unreliableTubes: make(map[byte]*Unreliable),
		tubeQueue:       make(chan Tube, 128),
		m:               sync.Mutex{},
		sendQueue:       make(chan []byte),
		state:           state,
		stopped:         make(chan struct{}),
		underlying:      msgConn,
		timeout:         timeout,
		log:             log,
		readBuf:         make([]byte, 65535),
		receiverErr:     make(chan error),
		senderErr:       make(chan error),
	}

	mux.state.Store(muxerRunning)
	mux.start()

	mux.log.WithField("timeout (ms)", mux.timeout.Milliseconds()).Info("Created Muxer")

	return mux
}

// waits for tubes to close and then removes them so their IDs can be reused
// reapTube is called in a goroutine whenever a tube is created or accepted.
func (m *Muxer) reapTube(t Tube) {
	t.WaitForClose()

	// This prevents tubes IDs from being reused while the remote peer is waiting in lastAck.
	if _, ok := t.(*Reliable); ok && t.GetID()%2 == m.idParity {
		timer := time.NewTimer(2 * retransmitOffset)
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
			m.log.WithField("tubeID", guess).Debug("picked new tube id")
			return guess, nil
		}
	}

	m.log.Warn("out of tube IDs")
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
	if err == nil {
		m.log.Infof("Created Tube: %v", tube.GetID())
	}
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
		recvWindow: newReceiver(tubeLog),
		sender:     newSender(tubeLog),
		sendQueue:  m.sendQueue,
		tType:      tType,
		log:        tubeLog,
	}
	r.lastAckSent.Store(0)
	r.sender.closed.Store(true)
	m.addTube(r)
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
	if err == nil {
		m.log.Infof("Created Tube: %v", tube.GetID())
	}
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

// start begins the sender and receiver goroutines
func (m *Muxer) start() {
	go m.sender()
	go m.receiver()
	m.log.Info("Muxer running!")
}

// receiver reads packet from the underlying MsgConn and forwards them to the relevant
// tubes. If it gets a REQ packet requesting a new tube, it creates that tube.
func (m *Muxer) receiver() {
	var err error

	// When start finishes, it sends its error on this channel.
	// m.Stop receives this error and passes it to the caller.
	defer func() {
		// This case indicates that the muxer was stopped by m.Stop()
		if m.state.Load() == muxerStopped {
			m.log.WithFields(logrus.Fields{
				"state": m.state.Load(),
				"error": err,
			}).Warn("muxer receiver stopping")
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
		var frame *frame
		frame, err = m.readMsg()
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
				tube.receive(frame)
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
	// This error indicates that the muxer got an ICMP Destination Unreachable packet.
	// This happens when the other side of the connetion has been closed, so we
	// can ignore it.
	// TODO(hosono) is it really ok to ignore net.ErrClosed?
	defer func() {
		if errors.Is(sendErr, net.ErrClosed) || errors.Is(sendErr, syscall.ECONNREFUSED) {
			sendErr = nil
		}
		if errors.Is(recvErr, net.ErrClosed) || errors.Is(recvErr, syscall.ECONNREFUSED) {
			recvErr = nil
		}
	}()

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

	close(m.sendQueue)
	close(m.tubeQueue)

	m.underlying.Close()

	// Cache error for future calls to Stop
	m.recvErr = <-m.receiverErr
	m.sendErr = <-m.senderErr
	m.m.Lock()
	defer m.m.Unlock()

	close(m.stopped)
	m.log.Info("Muxer.Stop() finished")
	return m.sendErr, m.recvErr
}
