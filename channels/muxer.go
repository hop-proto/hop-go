package channels

import (
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/transport"
)

type Muxer struct {
	channels map[byte]*Reliable
	// Channels waiting for an Accept() call.
	channelQueue chan *Reliable
	m            sync.Mutex
	// All hop channels write raw bytes for a channel packet to this golang chan.
	sendQueue  chan []byte
	stopped    bool
	underlying transport.MsgConn
	netConn    net.Conn
}

func NewMuxer(msgConn transport.MsgConn, netConn net.Conn) *Muxer {
	return &Muxer{
		channels:     make(map[byte]*Reliable),
		channelQueue: make(chan *Reliable, 128),
		m:            sync.Mutex{},
		sendQueue:    make(chan []byte),
		stopped:      false,
		underlying:   msgConn,
		netConn:      netConn,
	}
}

func (m *Muxer) addChannel(c *Reliable) {
	m.m.Lock()
	m.channels[c.id] = c
	m.m.Unlock()
}

func (m *Muxer) GetChannel(channelId byte) (*Reliable, bool) {
	m.m.Lock()
	defer m.m.Unlock()
	c, ok := m.channels[channelId]
	return c, ok
}

func (m *Muxer) CreateChannel(cType byte) (*Reliable, error) {
	r, err := NewReliableChannel(m.underlying, m.netConn, m.sendQueue, cType)
	m.addChannel(r)
	logrus.Infof("Created Channel: %v", r.id)
	return r, err
}

func (m *Muxer) Accept() (*Reliable, error) {
	s := <-m.channelQueue
	logrus.Infof("Accepted Channel: %v", s.id)
	return s, nil
}

func (m *Muxer) readMsg() (*Frame, error) {
	pkt := make([]byte, 65535)
	_, err := m.underlying.ReadMsg(pkt)
	if err != nil {
		return nil, err
	}
	return fromBytes(pkt)

}

func (m *Muxer) sender() {
	for !m.stopped {
		rawBytes := <-m.sendQueue
		m.underlying.WriteMsg(rawBytes)
	}
}

func (m *Muxer) Start() {
	go m.sender()
	m.stopped = false
	for !m.stopped {
		frame, err := m.readMsg()
		if err != nil {
			continue
		}
		channel, ok := m.GetChannel(frame.channelID)
		if !ok {
			//logrus.Info("NO CHANNEL")
			initFrame, err := fromInitiateBytes(frame.toBytes())

			if initFrame.flags.REQ {

				if err != nil {
					logrus.Panic(err)
					panic(err)
				}
				channel = NewReliableChannelWithChannelId(m.underlying, m.netConn, m.sendQueue, initFrame.channelType, initFrame.channelID)
				m.addChannel(channel)
				m.channelQueue <- channel
			}

		}

		if channel != nil {
			if frame.flags.REQ || frame.flags.RESP {
				initFrame, err := fromInitiateBytes(frame.toBytes())
				//logrus.Info("RECEIVING INITIATE FRAME ", initFrame.channelID, " ", initFrame.frameNo, " ", frame.flags.REQ, " ", frame.flags.RESP)
				if err != nil {
					panic(err)
				}
				go channel.receiveInitiatePkt(initFrame)
			} else {
				//logrus.Info("RECEIVING NORMAL FRAME")
				go channel.receive(frame)
			}
		}

	}
}

//Stop ensures all the muxer channels are closed
func (m *Muxer) Stop() {
	m.m.Lock()
	wg := sync.WaitGroup{}
	for _, v := range m.channels {
		wg.Add(1)
		go func(v *Reliable) { //parallelized closing channels because other side may close them in a different order
			defer wg.Done()
			logrus.Info("Closing channel: ", v.id)
			v.Close() //TODO(baumanl): If a channel was already closed this returns an error that is ignored atm. Remove channel from map after closing?
		}(v)
	}
	m.m.Unlock()
	wg.Wait()
	m.stopped = true //This has to come after all the channels are closed otherwise the channels can't finish sending all their frames and deadlock
	logrus.Info("Muxer.Stop() finished")
}
