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

func (m *Muxer) AddChannel(c *Reliable) {
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

func (m *Muxer) CreateChannel(windowSize uint16) (*Reliable, error) {
	r, err := NewReliableChannel(m.underlying, m.netConn, m.sendQueue, windowSize)
	m.AddChannel(r)
	return r, err
}

func (m *Muxer) Accept() (*Reliable, error) {
	return <-m.channelQueue, nil
}

func (m *Muxer) readMsg() (*Frame, error) {
	pkt := make([]byte, 65535)
	_, err := m.underlying.ReadMsg(pkt)
	if err != nil {
		return nil, err
	}
	return FromBytes(pkt)

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
			logrus.Info("NO CHANNEL")
			initFrame, err := FromInitiateBytes(frame.toBytes())

			if initFrame.flags.REQ {

				if err != nil {
					logrus.Panic(err)
					panic(err)
				}
				channel = NewReliableChannelWithChannelId(m.underlying, m.netConn, m.sendQueue, initFrame.windowSize, initFrame.channelID)
				m.AddChannel(channel)
				m.channelQueue <- channel
			}

		}

		if channel != nil {
			if frame.flags.REQ || frame.flags.RESP {
				initFrame, err := FromInitiateBytes(frame.toBytes())
				logrus.Info("RECEIVING INITIATE FRAME ", initFrame.channelID, " ", initFrame.frameNo, " ", frame.flags.REQ, " ", frame.flags.RESP)
				if err != nil {
					panic(err)
				}
				go channel.ReceiveInitiatePkt(initFrame)
			} else {
				logrus.Info("RECEIVING NORMAL FRAME")
				go channel.Receive(frame)
			}
		}

	}
}

func (m *Muxer) Stop() {
	m.m.Lock()
	m.stopped = true
	for _, v := range m.channels {
		v.Close()
	}
	m.m.Unlock()

}
