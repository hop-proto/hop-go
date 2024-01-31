package tubes

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"hop.computer/hop/common"
)

func BenchmarkReliable(b *testing.B) {
	logrus.SetOutput(io.Discard)

	t1, t2, stop, _, err := makeConn(1.0, true, b)
	assert.NilError(b, err)
	defer stop()

	wg := sync.WaitGroup{}

	size := 1 << 22
	b.SetBytes(int64(size))
	b.ReportAllocs()

	recvBuf := make([]byte, size)
	sendBuf := make([]byte, size)
	_, err = rand.Read(sendBuf)
	assert.NilError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		go func() {
			n := 0
			for n < size {
				nbytes, err := t1.Write(sendBuf[n:])
				n = n + nbytes
				assert.NilError(b, err)
			}
			assert.Equal(b, n, size)
			wg.Done()
		}()

		n := 0
		for n < size {
			nbytes, err := t2.Read(recvBuf[n:])
			n = n + nbytes
			assert.NilError(b, err)
		}
		wg.Wait()

		// This takes up 95% of benchmark time
		// assert.DeepEqual(b, sendBuf, recvBuf)
	}
}

func BenchmarkReceiver(b *testing.B) {
    packetSize := 1 << 13
    size := 1 << 18
    numMessages := size / packetSize
    r := receiver{
        dataReady:   common.NewDeadlineChan[struct{}](1),
        buffer:      new(bytes.Buffer),
        fragments:   make(PriorityQueue, 0),
        windowSize:  windowSize,
        windowStart: 1,
        log:         logrus.New().WithField("receiver", ""),
    }
    r.init()
    r.m.Lock()
    r.ackNo = 1
    r.m.Unlock()
    bufRead := make([]byte, packetSize)
    bufWrite := make([]byte, packetSize)
    b.SetBytes(int64(size))
    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        go func() {
            start := uint32(i * numMessages + 1)
            for i := uint32(0); i < uint32(numMessages); i++ {
                r.receive(&frame{
                    frameNo:    start + i,
                    data:       bufWrite,
                    dataLength: uint16(packetSize),
                })
            }
        }()
        for read := 0; read < numMessages; read++ {
            n, err := r.read(bufRead)
            assert.NilError(b, err)
            if n == 0 {
                n, err = r.read(bufRead)
            }
        }
    }
}
