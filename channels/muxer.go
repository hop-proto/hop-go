package channels

import (
	"zmap.io/portal/transport"
)

type Muxer struct {
	channels     map[byte]*Reliable
	channelQueue chan *Reliable
	// All hop channels write raw bytes for a channel packet to this golang chan.
	sendQueue  chan []byte
	stopped    bool
	underlying transport.MsgConn
}

func NewMuxer(underlying transport.MsgConn) *Muxer {
	return &Muxer{
		channels:     make(map[byte]*Reliable),
		channelQueue: make(chan *Reliable),
		sendQueue:    make(chan []byte),
		stopped:      false,
		underlying:   underlying,
	}
}

func (m *Muxer) CreateChannel(windowSize uint16) (*Reliable, error) {
	r, err := NewReliableChannel(m.underlying, m.sendQueue, windowSize)
	m.channels[r.cid] = r
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
		pkt, err := m.readMsg()
		if err != nil {
			continue
		}

		channel, ok := m.channels[pkt.channelID]
		if !ok {
			initPkt, err := FromInitiateBytes(pkt.toBytes())
			if err != nil {
				panic(err)
			}
			ch := NewReliableChannelWithChannelId(m.underlying, m.sendQueue, initPkt.windowSize, initPkt.channelID)
			m.channels[pkt.channelID] = ch
			m.channelQueue <- ch
			channel = ch
		} else {
			channel.Receive(pkt)
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
