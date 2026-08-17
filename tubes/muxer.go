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
	// tubeQueue contains remotely initiated tubes accepted by the receiver.
	// Once Stop publishes muxerStopping, the receiver cannot add another tube.
	tubeQueue chan Tube

	idParity byte

	m sync.Mutex
	// +checklocks:m
	reliableTubes map[byte]*Reliable
	// +checklocks:m
	unreliableTubes map[byte]*Unreliable

	// outbound is the only tube-to-Muxer admission path. Its queues are private
	// to the Muxer sender and are never closed.
	outbound *outbox
	state    atomic.Value
	// stopping is closed as soon as Stop wins lifecycle ownership. It wakes
	// receiver-side admissions without waiting for shutdown completion.
	stopping chan struct{}
	// stopped is closed after Stop caches both worker results.
	stopped    chan struct{}
	underlying transport.MsgConn
	timeout    time.Duration
	log        *logrus.Entry

	// senderErr receives once, after the sender stops or the transport write path fails.
	senderErr chan error
	sendErr   error

	// receiverErr receives once, after the receiver stops reading the transport.
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
		outbound:        newOutbox(),
		state:           state,
		stopping:        make(chan struct{}),
		stopped:         make(chan struct{}),
		underlying:      msgConn,
		timeout:         timeout,
		log:             log,
		readBuf:         make([]byte, 65535),
		receiverErr:     make(chan error, 1),
		senderErr:       make(chan error, 1),
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
	if r, ok := t.(*Reliable); ok && t.GetID()%2 == m.idParity {
		r.l.Lock()
		timer := time.NewTimer(4 * r.sender.RTT)
		r.l.Unlock()
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
		id:             tubeID,
		localAddr:      m.underlying.LocalAddr(),
		remoteAddr:     m.underlying.RemoteAddr(),
		tubeState:      created,
		initRecv:       make(chan struct{}),
		initDone:       make(chan struct{}),
		sendDone:       make(chan struct{}),
		closed:         make(chan struct{}),
		closeRequested: make(chan struct{}),
		recvWindow:     newReceiver(tubeLog),
		sender:         newSender(tubeLog),
		outbound:       m.outbound,
		tType:          tType,
		log:            tubeLog,
	}
	r.lastAckSent.Store(0)
	r.lastFrameSent.Store(0)
	r.sender.closed.Store(true)
	m.addTube(r)
	go r.initiate(req)

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
		outbound:     m.outbound,
		localAddr:    m.underlying.LocalAddr(),
		remoteAddr:   m.underlying.RemoteAddr(),
		recv:         common.NewDeadlineChan[[]byte](maxBufferedPackets),
		send:         common.NewDeadlineChan[[]byte](maxBufferedPackets),
		state:        atomic.Value{},
		initiated:    make(chan struct{}),
		initiateDone: make(chan struct{}),
		stopInitiate: make(chan struct{}),
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

	return tube, nil
}

// Accept blocks until a new tube is available or the muxer stops
// If the muxer stops, Accept will return a nil Tube and ErrMuxerStopping.
// Otherwise, it will return a valid tube that is ready for use.
func (m *Muxer) Accept() (Tube, error) {
	select {
	case <-m.stopping:
		return nil, ErrMuxerStopping
	default:
	}
	select {
	case tube := <-m.tubeQueue:
		select {
		case <-m.stopping:
			return nil, ErrMuxerStopping
		default:
			return tube, nil
		}
	case <-m.stopping:
		return nil, ErrMuxerStopping
	}
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

// sender is the sole receiver for outbox queues and the sole writer to the
// underlying MsgConn. Failure aborts both admission priorities atomically.
func (m *Muxer) sender() {
	var err error
	defer func() {
		m.log.WithField("error", err).Debug("muxer sender stopped")
		m.senderErr <- err
	}()

	for {
		var rawBytes []byte
		gotFrame := false

		// Prefer priority traffic when it is already waiting without starving
		// normal traffic when both arrive concurrently.
		select {
		case rawBytes = <-m.outbound.priority:
			gotFrame = true
		default:
		}

		if !gotFrame {
			select {
			case <-m.outbound.aborted:
				err = m.outbound.abortErr()
				return
			case <-m.outbound.stop:
				return
			case rawBytes = <-m.outbound.priority:
				gotFrame = true
			case rawBytes = <-m.outbound.normal:
				gotFrame = true
			}
		}

		err = m.underlying.WriteMsg(rawBytes)
		if err == nil {
			continue
		}

		m.log.Warnf("error in muxer sender. stopping muxer: %s", err)
		m.outbound.abort(err)
		go m.Stop()
		return
	}
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

	// When the receiver finishes, it sends its error on receiverErr. Stop
	// receives that result before publishing shutdown completion.
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
				if tube != nil {
					tube.getLog().Debug("added tube to queue")
					select {
					case m.tubeQueue <- tube:
					case <-m.stopping:
						return
					}
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

// this is a helper function for m.Stop().
func closeTubeHelper(t Tube, log *logrus.Entry, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(v Tube) { //parallelized closing tubes because other side may close them in a different order
		defer wg.Done()
		v.getLog().Info("Closing tube: ", v.GetID())
		err := v.Close()
		if err != nil && err != io.EOF {
			// Tried to close tube in bad state. Nothing to do
			log.Errorf("tube %d closed with error: %s", v.GetID(), err)
			return
		}
		v.WaitForClose()
	}(t)
}

// Stop gracefully closes every tube and then the underlying transport. Its
// bounded fallback may close the transport first to unblock that graceful
// drain. Calls are idempotent; concurrent callers wait for the elected shutdown
// owner to publish its result. Stop returns the sender error followed by the
// receiver error.
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

	for _, v := range m.reliableTubes {
		closeTubeHelper(v, m.log, &wg)
	}
	for _, v := range m.unreliableTubes {
		closeTubeHelper(v, m.log, &wg)
	}

	m.state.Store(muxerStopping)
	close(m.stopping)
	m.m.Unlock()

	// If tubes do not correctly close after some time, abort admission before
	// forcing lifecycle completion. This wakes both outbox priorities and any
	// producer blocked behind a transport write.
	fallback := time.AfterFunc(muxerTimeout, func() {
		if m.state.Load() == muxerStopped {
			return
		}

		m.outbound.abort(ErrMuxerStopping)
		m.underlying.Close()

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
	fallback.Stop()
	m.state.Store(muxerStopped)

	m.outbound.requestStop()

	// All tube producers have completed, so a graceful stop can terminate the
	// sender without closing data queues. A blocked transport write is bounded.
	senderTimer := time.NewTimer(muxerTimeout)
	select {
	case m.sendErr = <-m.senderErr:
		senderTimer.Stop()
	case <-senderTimer.C:
		m.outbound.abort(ErrMuxerStopping)
		m.underlying.Close()
		m.sendErr = <-m.senderErr
	}
	m.underlying.Close()

	// Cache errors for future calls to Stop.
	m.recvErr = <-m.receiverErr
	m.m.Lock()
	defer m.m.Unlock()

	close(m.stopped)
	m.log.Info("Muxer.Stop() finished")
	return m.sendErr, m.recvErr
}
