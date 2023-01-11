package tubes

import (
	"bytes"
	"math/rand"
	"sync"
	"testing"

	"gotest.tools/assert"

	"hop.computer/hop/common"

	"github.com/sirupsen/logrus"
)

func makePacket(frameNo uint32, b []byte) *dataFrame {
	pkt := dataFrame{
		dataLength: uint16(len(b)),
		frameNo:    frameNo,
		data:       b,
		flags: frameFlags{
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
	recvWindow := receiver{
		dataReady:   common.NewDeadlineChan[struct{}](1),
		buffer:      new(bytes.Buffer),
		fragments:   make(PriorityQueue, 0),
		windowSize:  200,
		windowStart: 1,
		log:         logrus.WithField("receiver", "test"),
	}
	recvWindow.init()

	dataLength := 1000
	packetLength := 5
	testData := make([]byte, dataLength)
	n, err := rand.Read(testData)
	assert.Equal(t, n, dataLength)
	assert.NilError(t, err)

	packets := make([]*dataFrame, dataLength/packetLength)
	i := 0
	frameNo := 1
	for i < dataLength/packetLength {
		packets[i] = makePacket(uint32(frameNo), testData[i*packetLength:i*packetLength+packetLength])
		i++
		frameNo++
	}
	rand.Shuffle(len(packets), func(i, j int) {
		packets[i], packets[j] = packets[j], packets[i]
	})

	wg := sync.WaitGroup{}
	for i = 0; i < len(packets); i++ {
		// See if receiver can handle retransmits
		wg.Add(2)

		go func(i int) {
			defer wg.Done()
			recvWindow.receive(packets[i])
		}(i)
		go func(i int) {
			defer wg.Done()
			recvWindow.receive(packets[i])
		}(i)
	}
	wg.Wait()

	readData := make([]byte, dataLength)
	n, err = recvWindow.read(readData)
	assert.Equal(t, n, dataLength)
	assert.NilError(t, err)
	assert.Equal(t, string(testData), string(readData))
}

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
