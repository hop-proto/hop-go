package tubes

import (
	"crypto/rand"
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
}

// NewMuxer starts a new tube muxer
func NewMuxer(msgConn transport.MsgConn, netConn net.Conn, timeout time.Duration, log *logrus.Entry) *Muxer {
	return &Muxer{
		tubes:      make(map[byte]Tube),
		tubeQueue:  make(chan Tube, 128),
		m:          sync.Mutex{},
		sendQueue:  make(chan []byte),
		underlying: msgConn,
		timeout:    timeout,
		log:        log,
	}
}

func (m *Muxer) addTube(c Tube) {
	m.m.Lock()
	m.tubes[c.GetID()] = c
	m.m.Unlock()
}

func (m *Muxer) getTube(tubeID byte) (Tube, bool) {
	m.m.Lock()
	defer m.m.Unlock()
	c, ok := m.tubes[tubeID]
	return c, ok
}

// CreateReliableTube starts a new reliable tube
func (m *Muxer) CreateReliableTube(tType TubeType) (*Reliable, error) {
	tube, err := newReliableTube(m.underlying, m.netConn, m.sendQueue, tType)
	m.addTube(tube)
	m.log.Infof("Created Tube: %v", tube.GetID())
	return tube, err
}

// CreateUnreliableTube starts a new unreliable tube
func (m *Muxer) CreateUnreliableTube(tType TubeType) (*Unreliable, error) {
	// TODO(hosono) we should pick tube IDs sequentially not randomly
	tubeID := []byte{0}
	rand.Read(tubeID)
	tube := m.makeUnreliableTubeWithID(tType, tubeID[0], true)
	m.log.Infof("Created Tube: %v", tube.GetID())
	return tube, nil
}

// req is true if the tube is a new request. False otherwise
func (m *Muxer) makeUnreliableTubeWithID(tType TubeType, tubeID byte, req bool) *Unreliable {
	tube := &Unreliable{
		tType:      tType,
		id:         tubeID,
		sendQueue:  m.sendQueue,
		localAddr:  m.netConn.LocalAddr(),
		remoteAddr: m.netConn.RemoteAddr(),
		recv:       common.NewDeadlineChan[[]byte](maxBufferedPackets),
		send:       common.NewDeadlineChan[[]byte](maxBufferedPackets),
		state:      atomic.Value{},
		initiated:  make(chan struct{}, 1),
		req:        req,
		log:        m.log.WithField("tube", tubeID),
	}
	go tube.initiate()
	m.addTube(tube)
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
	pkt := make([]byte, 65535) // TODO(hosono) avoid allocation
	_, err := m.underlying.ReadMsg(pkt)
	if err != nil {
		return nil, err
	}

	// Set timeout
	if m.timeout != 0 {
		m.underlying.SetReadDeadline(time.Now().Add(m.timeout))
	}
	return fromBytes(pkt)

}

func (m *Muxer) sender() {
	for !m.stopped.Load() {
		rawBytes := <-m.sendQueue
		m.underlying.WriteMsg(rawBytes)
	}
}

// Start allows a muxer to start listening and handling incoming tube requests and messages
func (m *Muxer) Start() (err error) {
	go m.sender()
	m.stopped.Store(false)

	defer func() {
		// This case indicates that the muxer was stopped by m.Close()
		if errors.Is(err, os.ErrDeadlineExceeded) && m.stopped.IsSet() {
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
			// TODO(hosono) Are there any recoverable errors? (os.ErrDeadlineExceeded isn't)
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
					// TODO(hosono) make these methods on the muxer
					tube = newReliableTubeWithTubeID(m.underlying, m.netConn, m.sendQueue, initFrame.tubeType, initFrame.tubeID)
					m.addTube(tube)
					m.tubeQueue <- tube
				} else {
					m.makeUnreliableTubeWithID(initFrame.tubeType, initFrame.tubeID, false)
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
				go tube.receiveInitiatePkt(initFrame)
			} else {
				// m.log.Info("RECEIVING NORMAL FRAME")
				// TODO(hosono) doing this in a gorouting messes up the nettests
				// so it's probably time to fork the nettests and be done with it
				tube.receive(frame)
			}
		}

	}
	return nil
}

// Close ensures all the muxer tubes are closed
func (m *Muxer) Close() (err error) {
	m.m.Lock()
	defer m.m.Unlock()
	if m.stopped.IsSet() {
		return io.EOF
	}
	wg := sync.WaitGroup{}
	for _, v := range m.tubes {
		wg.Add(1)
		go func(v Tube) { //parallelized closing tubes because other side may close them in a different order
			defer wg.Done()
			m.log.Info("Closing tube: ", v.GetID())
			v.Close() //TODO(baumanl): If a tube was already closed this returns an error that is ignored atm. Remove tube from map after closing?
		}(v)
	}
	wg.Wait()
	m.stopped.Store(true) //This has to come after all the tubes are closed otherwise the tubes can't finish sending all their frames and deadlock
	m.log.Info("Muxer.Stop() finished")
}
