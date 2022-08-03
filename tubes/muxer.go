package tubes

import (
	"errors" "fmt" "net" "os" "sync" "time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/transport"
)

//Muxer handles delivering and sending tube messages type Muxer struct {
	// +checklocks:m tubes map[byte]*Reliable // Channels waiting for
	an Accept() call.  tubeQueue chan *Reliable m	      sync.Mutex
	// All hop tubes write raw bytes for a tube packet to this
	golang chan.  sendQueue  chan []byte stopped	bool underlying
	transport.MsgConn netConn    net.Conn timeout	 time.Duration
}

//NewMuxer starts a new tube muxer func NewMuxer(msgConn
transport.MsgConn, netConn net.Conn, timeout time.Duration) *Muxer {
	return &Muxer{
		tubes:	    make(map[byte]*Reliable), tubeQueue:
		make(chan *Reliable, 128), m:	       sync.Mutex{},
		sendQueue:  make(chan []byte), stopped:    false,
		underlying: msgConn, netConn:	 netConn, timeout:
		timeout,
	}
}

func (m *Muxer) addTube(c *Reliable) {
	m.m.Lock() m.tubes[c.id] = c m.m.Unlock()
}

func (m *Muxer) getTube(tubeID byte) (*Reliable, bool) {
	m.m.Lock() defer m.m.Unlock() c, ok := m.tubes[tubeID] return
	c, ok
}

//CreateTube starts a new reliable tube func (m *Muxer) CreateTube(tType
TubeType) (*Reliable, error) {
	r, err := newReliableTube(m.underlying, m.netConn, m.sendQueue,
	tType) m.addTube(r) logrus.Infof("Created Tube: %v", r.id)
	return r, err
}

//Accept blocks for and accepts a new reliable tube func (m *Muxer)
Accept() (*Reliable, error) {
	s := <-m.tubeQueue logrus.Infof("Accepted Tube: %v", s.id)
	return s, nil
}

func (m *Muxer) readMsg() (*frame, error) {
	pkt := make([]byte, 65535) _, err := m.underlying.ReadMsg(pkt)
	if err != nil {
		return nil, err
	}

	// Set timeout if m.timeout != 0 {
		m.underlying.SetReadDeadline(time.Now().Add(m.timeout))
	} return fromBytes(pkt)

}

func (m *Muxer) sender() {
	for !m.stopped {
		rawBytes := <-m.sendQueue m.underlying.WriteMsg(rawBytes)
	}
}

//Start allows a muxer to start listening and handling incoming tube
requests and messages func (m *Muxer) Start() error {
	go m.sender() m.stopped = false

	// Set initial timeout if m.timeout != 0 {
		m.underlying.SetReadDeadline(time.Now().Add(m.timeout))
	} for !m.stopped {
		frame, err := m.readMsg() if err != nil {
			// TODO(hosono) Are there any recoverable errors?
			if errors.Is(err, os.ErrDeadlineExceeded) { //
			if error is a timeout
				return fmt.Errorf("connection timed out:
				%s", err)
			}
      return fmt.Errorf("error in Muxer: %s", err)
		}
		tube, ok := m.getTube(frame.tubeID)
		if !ok {
			//logrus.Info("NO CHANNEL")
			initFrame, err := fromInitiateBytes(frame.toBytes())

			if initFrame.flags.REQ {

				if err != nil {
					return err
				}
				tube = newReliableTubeWithTubeID(m.underlying, m.netConn, m.sendQueue, initFrame.tubeType, initFrame.tubeID)
				m.addTube(tube)
				m.tubeQueue <- tube
			}

		}

		if tube != nil {
			if frame.flags.REQ || frame.flags.RESP {
				initFrame, err := fromInitiateBytes(frame.toBytes())
				//logrus.Info("RECEIVING INITIATE FRAME ", initFrame.tubeID, " ", initFrame.frameNo, " ", frame.flags.REQ, " ", frame.flags.RESP)
				if err != nil {
					return err
				}
				go tube.receiveInitiatePkt(initFrame)
			} else {
				//logrus.Info("RECEIVING NORMAL FRAME")
				go tube.receive(frame)
			}
		}

	}
	return nil
}

//Stop ensures all the muxer tubes are closed
func (m *Muxer) Stop() {
	m.m.Lock()
	wg := sync.WaitGroup{}
	for _, v := range m.tubes {
		wg.Add(1)
		go func(v *Reliable) { //parallelized closing tubes because other side may close them in a different order
			defer wg.Done()
			logrus.Info("Closing tube: ", v.id)
			v.Close() //TODO(baumanl): If a tube was already closed this returns an error that is ignored atm. Remove tube from map after closing?
		}(v)
	}
	m.m.Unlock()
	wg.Wait()
	m.stopped = true //This has to come after all the tubes are closed otherwise the tubes can't finish sending all their frames and deadlock
	logrus.Info("Muxer.Stop() finished")
}
