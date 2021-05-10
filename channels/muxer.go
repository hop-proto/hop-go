package channels

import (
	"zmap.io/portal/transport"
)

type Muxer struct {
	channels     map[byte]*Reliable
	stopped      bool
	channelQueue chan *Reliable
	underlying   transport.MsgConn
}

func NewMuxer(stopped bool, underlying transport.MsgConn) *Muxer {
	return &Muxer{make(map[byte]*Reliable), stopped, make(chan *Reliable), underlying}
}

func (m *Muxer) CreateChannel() (*Reliable, error) {
	r, err := NewReliableChannel(m.underlying, m)
	if err == nil {
		r.Initiate()
	}
	return r, err
}

func (m *Muxer) Accept() (*Reliable, error) {
	return <-m.channelQueue, nil
}

func (m *Muxer) readMsg() (*Packet, error) {
	pkt := make([]byte, 65535)
	_, err := m.underlying.ReadMsg(pkt) // wait until read packet
	if err != nil {
		return nil, err
	}
	return FromBytes(pkt)

}

func (m *Muxer) Start() {
	m.stopped = false
	for !m.stopped {
		pkt, err := m.readMsg()
		if err != nil {
			continue
		}

		channel, ok := m.channels[pkt.channelID]
		if !ok {
			ch := NewReliableChannelWithChannelId(m.underlying, m, pkt.channelID)
			m.channels[pkt.channelID] = ch
			m.channelQueue <- ch
			channel = ch
		} else {
			channel.ordered.Write(pkt.data)
		}

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
