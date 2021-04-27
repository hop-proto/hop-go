package channels

import (
	"github.com/sirupsen/logrus"
	"zmap.io/portal/transport"
)

type Muxer struct {
	channels     map[uint64]*Reliable
	stopped      bool
	channelQueue chan *Reliable
	underlying   transport.MsgConn
}

type msg struct {
	ChannelID  uint64
	SequenceNo int
	Data       []byte
}

func (m *Muxer) CreateChannel() (*Reliable, error) {
	return NewReliableChannel(m.underlying)
}

func (m *Muxer) Accept() (*Reliable, error) {
	return <-m.channelQueue, nil
}

func (m *Muxer) readMsg() (*msg, error) {
	// Otherwise
	pkt := make([]byte, 65535)
	_, err := m.underlying.ReadMsg(pkt) // wait until read packet
	if err != nil {
		return nil, err
	}
	// TODO(drew): Parse the packet structure
	// Read the header
	// Extract the actual data
	return &msg{
		SequenceNo: 8,
		Data:       pkt,
	}, nil
}

func (m *Muxer) Start() {
	m.stopped = false
	for !m.stopped {
		rawMsg, err := m.readMsg()
		if err != nil {
			logrus.Fatal(err.Error())
			continue
		}
		logrus.Debugf("got msg for channel %x", rawMsg.ChannelID)
		channel, ok := m.channels[rawMsg.ChannelID]
		if !ok {
			ch := NewReliableChannelWithChannelId(m.underlying, rawMsg.ChannelID)
			m.channels[rawMsg.ChannelID] = ch
			m.channelQueue <- ch
		}
		logrus.Debugf("got channel %v", channel)
		// Inspect
		// Reorder here rawMsg.SequenceNumber
		// Add to some buffer???
		// if rawMsg.SequenceNo == nextNumber {
		// channel.pending.Write(rawMsg)
		// } else {
		// Packet is out of order
		// Buffer somewhere until we read the next packet
		// Then write everything to the pending queue once it's in order
		// }
	}
}
