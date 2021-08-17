package tubes

import (
	"bytes"
	"math/rand"
	"sync"
	"testing"

	"gotest.tools/assert"
)

func makePacket(frameNo uint32, b []byte) *Frame {
	pkt := Frame{
		dataLength: uint16(len(b)),
		frameNo:    frameNo,
		data:       b,
		flags: FrameFlags{
			ACK:  false,
			FIN:  false,
			REQ:  false,
			RESP: false,
		},
	}
	return &pkt
}

/* Tests that the receive window can handle highly concurrent and out of order packet receipts */
func TestReceiveWindow(t *testing.T) {
	recvWindow := Receiver{
		buffer: new(bytes.Buffer),
		bufferCond: sync.Cond{
			L: &sync.Mutex{},
		},
		fragments:   make(PriorityQueue, 0),
		windowSize:  200,
		windowStart: 1,
	}
	recvWindow.init()

	DATA_LENGTH := 1000
	PACKET_LENGTH := 5
	testData := make([]byte, DATA_LENGTH)
	for i := range testData {
		testData[i] = []byte{'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r'}[rand.Intn(6)]
	}

	packets := make([]*Frame, DATA_LENGTH/PACKET_LENGTH)
	i := 0
	frameNo := 1
	for i < DATA_LENGTH/PACKET_LENGTH {
		packets[i] = makePacket(uint32(frameNo), testData[i*PACKET_LENGTH:i*PACKET_LENGTH+PACKET_LENGTH])
		go recvWindow.receive(packets[i])
		// See if receiver can handle retransmits
		go recvWindow.receive(packets[i])
		i += 1
		frameNo += 1
	}

	readData := make([]byte, DATA_LENGTH)
	n, err := recvWindow.read(readData)
	assert.Equal(t, n, DATA_LENGTH)
	assert.NilError(t, err)
	assert.Equal(t, string(testData), string(readData))

}
