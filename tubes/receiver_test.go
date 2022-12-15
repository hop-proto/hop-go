package tubes

import (
	//"bytes"
	//"math/rand"
	//"sync"
	"testing"

	"gotest.tools/assert"

	"github.com/sirupsen/logrus"
)

// func makePacket(frameNo uint32, b []byte) *frame {
// 	pkt := frame{
// 		dataLength: uint16(len(b)),
// 		frameNo:    frameNo,
// 		data:       b,
// 		flags: frameFlags{
// 			ACK:  false,
// 			FIN:  false,
// 			REQ:  false,
// 			RESP: false,
// 		},
// 	}
// 	return &pkt
// }

// /* Tests that the receive window can handle highly concurrent and out of order packet receipts */
// func TestReceiveWindow(t *testing.T) {
// 	recvWindow := receiver{
// 		buffer: new(bytes.Buffer),
// 		bufferCond: sync.Cond{
// 			L: &sync.Mutex{},
// 		},
// 		fragments:   make(PriorityQueue, 0),
// 		windowSize:  200,
// 		windowStart: 1,
// 	}
// 	recvWindow.init()

// 	dataLength := 1000
// 	packetLength := 5
// 	testData := make([]byte, dataLength)
// 	for i := range testData {
// 		testData[i] = []byte{'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r'}[rand.Intn(6)]
// 	}

// 	packets := make([]*frame, dataLength/packetLength)
// 	i := 0
// 	frameNo := 1
// 	for i < dataLength/packetLength {
// 		packets[i] = makePacket(uint32(frameNo), testData[i*packetLength:i*packetLength+packetLength])
// 		go recvWindow.receive(packets[i])
// 		// See if receiver can handle retransmits
// 		go recvWindow.receive(packets[i])
// 		i++
// 		frameNo++
// 	}

// 	readData := make([]byte, dataLength)
// 	n, err := recvWindow.read(readData)
// 	assert.Equal(t, n, dataLength)
// 	assert.NilError(t, err)
// 	assert.Equal(t, string(testData), string(readData))

// }

func TestUnwrap(t *testing.T) {
	r := receiver{}
	r.ackNo = 0

	r.m.Lock()
	defer r.m.Unlock()

	var i uint64

	logrus.WithField("ackNo", r.ackNo).Info("setting ackNo")
	for i = 0; i < 1000; i++ {
		guess := r.unwrapFrameNo(uint32(i))
		assert.DeepEqual(t, guess, i)
	}

	r.ackNo = 1 << 31
	logrus.WithField("ackNo", r.ackNo).Info("setting ackNo")
	for i = r.ackNo - 500; i < r.ackNo+500; i++ {
		guess := r.unwrapFrameNo(uint32(i))
		assert.DeepEqual(t, guess, i)
	}

	r.ackNo = 1<<32 - 1
	logrus.WithField("ackNo", r.ackNo).Info("setting ackNo")
	for i = r.ackNo - 500; i < r.ackNo+500; i++ {
		guess := r.unwrapFrameNo(uint32(i))
		assert.DeepEqual(t, guess, i)
	}

	r.ackNo = 1 << 32
	logrus.WithField("ackNo", r.ackNo).Info("setting ackNo")
	for i = r.ackNo - 500; i < r.ackNo+500; i++ {
		guess := r.unwrapFrameNo(uint32(i))
		assert.DeepEqual(t, guess, i)
	}

	r.ackNo = 1<<32 + 1
	logrus.WithField("ackNo", r.ackNo).Info("setting ackNo")
	for i = r.ackNo - 500; i < r.ackNo+500; i++ {
		guess := r.unwrapFrameNo(uint32(i))
		assert.DeepEqual(t, guess, i)
	}
}
