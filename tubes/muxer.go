package tubes

import (
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/common"
	"hop.computer/hop/transport"
)

// Muxer handles delivering and sending tube messages
type Muxer struct {
	// +checklocks:m
	tubes map[byte]*Reliable
	// Channels waiting for an Accept() call.
	tubeQueue chan *Reliable
	m         sync.Mutex
	// All hop tubes write raw bytes for a tube packet to this golang chan.
	sendQueue  chan []byte
	stopped    common.AtomicBool // TODO(hosono) should this be defined elsewhere?
	underlying transport.MsgConn
	timeout    time.Duration
	muxerStopped chan struct{}
	// +checklocks:m
	nextTubeID   byte
}

// NewMuxer starts a new tube muxer
func NewMuxer(msgConn transport.MsgConn, timeout time.Duration) *Muxer {
	return &Muxer{
		tubes:      make(map[byte]*Reliable),
		tubeQueue:  make(chan *Reliable, 128),
		m:          sync.Mutex{},
		sendQueue:  make(chan []byte),
		stopped:    0, // false
		underlying: msgConn,
		timeout:    timeout,
		muxerStopped: make(chan struct{}, 1),
	}
}

func (m *Muxer) addTube(c *Reliable) {
	m.m.Lock()
	m.tubes[c.id] = c
	m.m.Unlock()
}

func (m *Muxer) getTube(tubeID byte) (*Reliable, bool) {
	m.m.Lock()
	defer m.m.Unlock()
	c, ok := m.tubes[tubeID]
	return c, ok
}

// if tubeID is nil, this creates a requesting tube and selects an id
func (m *Muxer) newReliableTube(tubeType TubeType, tubeID *byte) *Reliable {
	m.m.Lock()
	defer m.m.Unlock()

	laddr := m.underlying.LocalAddr()
	raddr := m.underlying.RemoteAddr()

	// whether the tube is requesting to initiate (true) or responding (false)
	req := tubeID == nil

	if tubeID == nil {
		tubeID = new(byte)
		tubeID = &m.nextTubeID
		
		for i := 0; i < 256; i += 2 {
			*tubeID += byte(i)
			_, ok := m.tubes[*tubeID]
			if !ok {
				break
			}
		}
	}

	r := makeTube(tubeType, *tubeID, laddr, raddr, m.sendQueue)
	m.tubes[r.id] = r
	go r.initiate(req)
	return r
}

// CreateTube starts a new reliable tube
func (m *Muxer) CreateTube(tubeType TubeType) *Reliable {
	r := m.newReliableTube(tubeType, nil)
	logrus.Infof("Created Tube: %v", r.id)
	return r
}

// Accept blocks for and accepts a new reliable tube
func (m *Muxer) Accept() (*Reliable, error) {
	s := <-m.tubeQueue
	logrus.Infof("Accepted Tube: %v", s.id)
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
	for rawBytes := range(m.sendQueue) {
		m.underlying.WriteMsg(rawBytes)
	}
}

// Start allows a muxer to start listening and handling incoming tube requests and messages
func (m *Muxer) Start() (err error) {
	go m.sender()
	m.stopped.SetFalse()

	defer func() {
		// This case indicates that the muxer was stopped by m.Close()
		if errors.Is(err, os.ErrDeadlineExceeded) && m.stopped.IsSet() {
			err = nil
		} else if err != nil {
			logrus.Errorf("Muxer ended with error: %s", err)
			m.Stop()
		}
	}()

	defer func() { m.muxerStopped <- struct{}{} }()

	// Set initial timeout
	if m.timeout != 0 {
		m.underlying.SetReadDeadline(time.Now().Add(m.timeout))
	}
	for !m.stopped.IsSet() {
		frame, err := m.readMsg()
		if err != nil {
			// TODO(hosono) Are there any recoverable errors? (os.ErrDeadlineExceeded isn't)
			return err
		}
		tube, ok := m.getTube(frame.tubeID)
		if !ok {
			//logrus.Info("NO CHANNEL")
			initFrame, err := fromInitiateBytes(frame.toBytes())

			if initFrame.flags.REQ {

				if err != nil {
					return err
				}
				tube = m.newReliableTube(initFrame.tubeType, &initFrame.tubeID)
				m.addTube(tube)
				m.tubeQueue <- tube
			}

		}

		if tube != nil {
			if frame.flags.REQ || frame.flags.RESP {
				initFrame, err := fromInitiateBytes(frame.toBytes())
				logrus.Debugf("receiving initiate frame. id: %d, frameNo: %d, req? %t, resp? %t", initFrame.tubeID, initFrame.frameNo, frame.flags.REQ, frame.flags.RESP)
				if err != nil {
					return err
				}
				tube.receiveInitiatePkt(initFrame)
			} else {
				logrus.Tracef("got frame. id: %d, ackno: %d. ack? %t", tube.id, frame.ackNo, frame.flags.ACK)
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
		go func(v *Reliable) { //parallelized closing tubes because other side may close them in a different order
			defer wg.Done()
			logrus.Info("Closing tube: ", v.id)
			v.Close() //TODO(baumanl): If a tube was already closed this returns an error that is ignored atm. Remove tube from map after closing?
		}(v)
	}
	wg.Wait()

	m.stopped.SetTrue() //This has to come after all the tubes are closed otherwise the tubes can't finish sending all their frames and deadlock
	m.underlying.SetReadDeadline(time.Now())
	<-m.muxerStopped

	close(m.sendQueue)

	logrus.Info("Muxer.Close() finished")
	return nil
}

func (m *Muxer) Stop() (err error) {
	m.m.Lock()
	defer m.m.Unlock()
	if m.stopped.IsSet() {
		return io.EOF
	}
	for _, tube := range(m.tubes) {
		tube.Reset()
	}
	m.stopped.SetTrue()
	m.underlying.SetReadDeadline(time.Now())
	<-m.muxerStopped
	close(m.sendQueue)
	return nil
}
