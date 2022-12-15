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

const (
	muxerRunning muxerState = iota
	muxerClosing muxerState = iota
	muxerClosed  muxerState = iota
)

// Tube interface is shared between Reliable and Unreliable Tubes
type Tube interface {
	net.Conn
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
	idParity byte
	// +checklocks:m
	tubes map[byte]Tube
	// Channels waiting for an Accept() call.
	tubeQueue chan Tube
	m         sync.Mutex
	// All hop tubes write raw bytes for a tube packet to this golang chan.
	sendQueue  chan []byte
	state      atomic.Value
	stopped    chan struct{}
	underlying transport.MsgConn
	timeout    time.Duration
	log        *logrus.Entry

	// This buffer is only used in m.readMsg
	readBuf []byte
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
	state.Store(muxerRunning)
	return &Muxer{
		idParity:   idParity,
		tubes:      make(map[byte]Tube),
		tubeQueue:  make(chan Tube, 128),
		m:          sync.Mutex{},
		sendQueue:  make(chan []byte),
		state:      state,
		stopped:    make(chan struct{}),
		underlying: msgConn,
		timeout:    timeout,
		log:        log,
		readBuf:    make([]byte, 65535),
	}
}

// waits for tubes to close and then removes them so their IDs can be reused
func (m *Muxer) reapTube(t Tube) {
	t.WaitForClose()

	// This prevents tubes IDs from being reused while the remote peer is in the timeWait state
	if t.GetID()%2 == m.idParity {
		time.Sleep(timeWaitTime)
	}

	m.m.Lock()
	defer m.m.Unlock()
	delete(m.tubes, t.GetID())
}

// +checklocks:m.m
func (m *Muxer) addTube(c Tube) {
	m.tubes[c.GetID()] = c
	go m.reapTube(c)
}

func (m *Muxer) getTube(tubeID byte) (Tube, bool) {
	m.m.Lock()
	defer m.m.Unlock()
	c, ok := m.tubes[tubeID]
	return c, ok
}

// +checklocks:m.m
func (m *Muxer) pickTubeID() (byte, error) {
	for guessInt := int(m.idParity); guessInt < 256; guessInt += 2 {
		guess := byte(guessInt)
		_, ok := m.tubes[guess]
		if !ok {
			m.log.WithField("tubeID", guess).Debug("picked new tube id")
			return guess, nil
		}
	}
	m.log.Info("out of tube IDs")
	return 0, ErrOutOfTubes
}

// CreateReliableTube starts a new reliable tube
func (m *Muxer) CreateReliableTube(tType TubeType) (*Reliable, error) {
	m.m.Lock()
	defer m.m.Unlock()
	id, err := m.pickTubeID()
	if err != nil {
		return nil, err
	}
	tube, err := m.makeReliableTubeWithID(tType, id, true)
	if err != nil {
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

	tubeID, err := m.pickTubeID()
	if err != nil {
		return nil, err
	}
	tube, nil := m.makeUnreliableTubeWithID(tType, tubeID, true)
	if err != nil {
		m.log.Infof("Created Tube: %v", tube.GetID())
	}
	return tube, err
}

// req is true if the tube is a new request. False otherwise
// +checklocks:m.m
func (m *Muxer) makeUnreliableTubeWithID(tType TubeType, tubeID byte, req bool) (*Unreliable, error) {
	if m.state.Load() != muxerRunning {
		m.log.WithField("tube", tubeID).Debug("tried to make tube while muxer is stopping")
		return nil, ErrMuxerStopping
	}
	tube := &Unreliable{
		tType:       tType,
		id:          tubeID,
		sendQueue:   m.sendQueue,
		localAddr:   m.underlying.LocalAddr(),
		remoteAddr:  m.underlying.RemoteAddr(),
		recv:        common.NewDeadlineChan[[]byte](maxBufferedPackets),
		send:        common.NewDeadlineChan[[]byte](maxBufferedPackets),
		state:       atomic.Value{},
		initiated:   make(chan struct{}),
		senderEnded: make(chan struct{}),
		closed:      make(chan struct{}),
		req:         req,
		log: m.log.WithFields(logrus.Fields{
			"tube":     tubeID,
			"reliable": false,
			"tubeType": tType,
		}),
	}
	m.addTube(tube)
	go tube.initiate()
	if !req {
		tube.getLog().WithField("tube", tube.GetID()).Debug("added tube to queue")
		m.tubeQueue <- tube
	}
	return tube, nil
}

// Accept blocks for and accepts a new tube
func (m *Muxer) Accept() (Tube, error) {
	s := <-m.tubeQueue
	m.log.Infof("Accepted Tube: %v", s.GetID())
	return s, nil
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
	for m.state.Load() != muxerClosed {
		select {
		case rawBytes := <-m.sendQueue:
			m.underlying.WriteMsg(rawBytes)
		case <-m.stopped:
			return
		}
	}
}

// Start allows a muxer to start listening and handling incoming tube requests and messages
func (m *Muxer) Start() (err error) {
	go m.sender()

	defer func() {
		// This case indicates that the muxer was stopped by m.Stop()
		if m.state.Load() == muxerClosed {
			err = nil
		} else if err != nil {
			m.log.Errorf("Muxer ended with error: %s", err)
			m.Stop()
		}
	}()

	// Set initial timeout
	if m.timeout != 0 {
		m.underlying.SetReadDeadline(time.Now().Add(m.timeout))
	}
	for m.state.Load() != muxerClosed {
		frame, err := m.readMsg()
		if err != nil {
			return err
		}
		var tube Tube
		tube, ok := m.getTube(frame.tubeID)
		if !ok {
			m.log.WithField("tube", frame.tubeID).Info("tube not found")
			initFrame := fromInitiateBytes(frame.toBytes())

			if initFrame.flags.REQ {

				if err != nil {
					return err
				}
				if initFrame.flags.REL {
					m.m.Lock()
					tube, err = m.makeReliableTubeWithID(initFrame.tubeType, initFrame.tubeID, false)
					m.m.Unlock()
				} else {
					m.m.Lock()
					tube, err = m.makeUnreliableTubeWithID(initFrame.tubeType, initFrame.tubeID, false)
					m.m.Unlock()
				}
			}
		}

		// Checking for tube != nil doesn't work because nil has a type
		// This means we have to check every possible type that tube could have
		if err == nil && tube != nil && tube != (*Reliable)(nil) && tube != (*Unreliable)(nil) {
			if frame.flags.REQ || frame.flags.RESP {
				initFrame := fromInitiateBytes(frame.toBytes())
				// m.log.Info("RECEIVING INITIATE FRAME ", initFrame.tubeID, " ", initFrame.frameNo, " ", frame.flags.REQ, " ", frame.flags.RESP)
				if err != nil {
					return err
				}
				tube.receiveInitiatePkt(initFrame)
			} else {
				go tube.receive(frame)
			}
		}

	}

	return nil
}

// Stop ensures all the muxer tubes are closed
func (m *Muxer) Stop() (err error) {
	m.m.Lock()
	m.log.Infof("Stopping muxer. %d tubes to close", len(m.tubes))

	if m.state.Load() != muxerRunning {
		m.m.Unlock()
		return io.EOF
	}
	wg := sync.WaitGroup{}
	stop := make(chan struct{})
	for _, v := range m.tubes {
		wg.Add(1)
		go func(v Tube) { //parallelized closing tubes because other side may close them in a different order
			defer wg.Done()
			m.log.Info("Closing tube: ", v.GetID())
			err := v.Close()
			if err != nil {
				// Tried to close tube in bad state. Nothing to do
				return
			}
			rel, ok := v.(*Reliable)
			if ok {
				select {
				case <-rel.closed:
					break
				case <-stop:
					break
				}
			}
		}(v)
	}
	m.state.Store(muxerClosing)
	m.m.Unlock()

	time.AfterFunc(muxerTimeout, func() {
		m.m.Lock()
		for _, v := range m.tubes {
			if t, ok := v.(*Reliable); ok {
				t.l.Lock()
				defer t.l.Unlock()
				t.getLog().Error("Timed out. Forcing close")
				t.enterClosedState()
			}
		}
		close(stop)
		m.m.Unlock()
	})

	wg.Wait()
	m.state.Store(muxerClosed)

	// TODO(hosono) uncommenting this line fixes issue #44, but it causes failure in the testing environment
	//m.underlying.Close()

	close(m.stopped)
	m.log.Info("Muxer.Stop() finished")
	return nil
}
