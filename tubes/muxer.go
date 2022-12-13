package tubes

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
	"hop.computer/hop/transport"
)

// Tube interface is shared between Reliable and Unreliable Tubes
type Tube interface {
	net.Conn
	receiveInitiatePkt(*initiateFrame) error
	receive(*frame) error
	Type() TubeType
	GetID() byte
	IsReliable() bool
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
	stopped    atomic.Bool
	underlying transport.MsgConn
	timeout    time.Duration
	log        *logrus.Entry

	// This buffer is only used in m.readMsg
	readBuf []byte
}

// NewMuxer starts a new tube muxer
func NewMuxer(msgConn transport.MsgConn, timeout time.Duration, is_server bool, log *logrus.Entry) *Muxer {
	var idParity byte
	if is_server {
		idParity = 0
	} else {
		idParity = 1
	}
	return &Muxer{
		idParity:   idParity,
		tubes:      make(map[byte]Tube),
		tubeQueue:  make(chan Tube, 128),
		m:          sync.Mutex{},
		sendQueue:  make(chan []byte),
		underlying: msgConn,
		timeout:    timeout,
		log:        log,
		readBuf:    make([]byte, 65535),
	}
}

// +checklocks:m.m
func (m *Muxer) addTube(c Tube) {
	m.tubes[c.GetID()] = c
}

func (m *Muxer) getTube(tubeID byte) (Tube, bool) {
	m.m.Lock()
	defer m.m.Unlock()
	c, ok := m.tubes[tubeID]
	return c, ok
}

// +checklocks:m.m
func (m *Muxer) pickTubeID() (byte, error) {
	for guess := m.idParity; guess+1 > guess; guess++ {
		_, ok := m.tubes[guess]
		if !ok {
			m.log.WithField("tubeID", guess).Debug("picked new tube id")
			return guess, nil
		}
	}
	m.log.Info("out of tube IDs")
	return 0, errors.New("out of tubes")
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
	m.log.Infof("Created Tube: %v", tube.GetID())
	return tube, err
}

// +checklocks:m.m
func (m *Muxer) makeReliableTubeWithID(tType TubeType, tubeID byte, req bool) (*Reliable, error) {
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
			// closed defaults to false
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
	m.addTube(r)
	r.recvWindow.init()
	go r.initiate(req)
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
	tube := m.makeUnreliableTubeWithID(tType, tubeID, true)
	m.log.Infof("Created Tube: %v", tube.GetID())
	return tube, nil
}

// req is true if the tube is a new request. False otherwise
// +checklocks:m.m
func (m *Muxer) makeUnreliableTubeWithID(tType TubeType, tubeID byte, req bool) *Unreliable {
	tube := &Unreliable{
		tType:      tType,
		id:         tubeID,
		sendQueue:  m.sendQueue,
		localAddr:  m.underlying.LocalAddr(),
		remoteAddr: m.underlying.RemoteAddr(),
		recv:       common.NewDeadlineChan[[]byte](maxBufferedPackets),
		send:       common.NewDeadlineChan[[]byte](maxBufferedPackets),
		state:      atomic.Value{},
		initiated:  make(chan struct{}),
		req:        req,
		log: m.log.WithFields(logrus.Fields{
			"tube":     tubeID,
			"reliable": false,
			"tubeType": tType,
		}),
	}
	m.addTube(tube)
	go tube.initiate()
	if !req {
		m.tubeQueue <- tube
	}
	return tube
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
	for !m.stopped.Load() {
		rawBytes := <-m.sendQueue
		m.underlying.WriteMsg(rawBytes)
	}
}

// Start allows a muxer to start listening and handling incoming tube requests and messages
// TODO(hosono) refactor this because I can't read it
func (m *Muxer) Start() (err error) {
	go m.sender()
	m.stopped.Store(false)

	defer func() {
		// This case indicates that the muxer was stopped by m.Close()
		if m.stopped.Load() {
			// TODO(hosono) should errors during Stop affect the return value of Start?
			err = nil
		} else if err != nil {
			logrus.Errorf("Muxer ended with error: %s", err)
			m.Stop()
		}
	}()

	// Set initial timeout
	if m.timeout != 0 {
		m.underlying.SetReadDeadline(time.Now().Add(m.timeout))
	}
	for !m.stopped.Load() {
		frame, err := m.readMsg()
		if err != nil {
			return err
		}
		tube, ok := m.getTube(frame.tubeID)
		if !ok {
			m.log.WithField("tube", frame.tubeID).Info("tube not found")
			initFrame, err := fromInitiateBytes(frame.toBytes())

			if initFrame.flags.REQ {

				if err != nil {
					return err
				}
				if initFrame.flags.REL {
					m.m.Lock()
					tube, _ = m.makeReliableTubeWithID(initFrame.tubeType, initFrame.tubeID, false)
					// TODO(hosono) error handling
					m.tubeQueue <- tube
					m.m.Unlock()
				} else {
					m.m.Lock()
					m.makeUnreliableTubeWithID(initFrame.tubeType, initFrame.tubeID, false)
					m.m.Unlock()
				}
			}

		}

		if tube != nil {
			if frame.flags.REQ || frame.flags.RESP {
				initFrame, err := fromInitiateBytes(frame.toBytes())
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
	defer m.m.Unlock()

	if m.stopped.Load() {
		return io.EOF
	}
	wg := sync.WaitGroup{}
	for _, v := range m.tubes {
		wg.Add(1)
		go func(v Tube) { //parallelized closing tubes because other side may close them in a different order
			defer wg.Done()
			m.log.Info("Closing tube: ", v.GetID())
			err := v.Close() //TODO(baumanl): If a tube was already closed this returns an error that is ignored atm. Remove tube from map after closing?
			if err != nil {
				// Tried to close tube in bad state. Nothing to do
				return
			}
			rel, ok := v.(*Reliable)
			if ok {
				rel.WaitForClose()
			}
		}(v)
	}
	wg.Wait()
	m.stopped.Store(true) //This has to come after all the tubes are closed otherwise the tubes can't finish sending all their frames and deadlock
	m.log.Info("Muxer.Stop() finished")
	return nil
}
