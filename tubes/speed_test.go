package tubes

import (
	"bytes"
	"container/heap"
	"crypto/rand"
	"encoding/binary"
	"github.com/sirupsen/logrus"
	"io"
	"sync"
	"testing"
	"time"

	"gotest.tools/assert"
)

func TestFileTransferSpeedReliableTubes(t *testing.T) {
	logrus.SetOutput(io.Discard)
	//logrus.SetLevel(logrus.TraceLevel)

	fileSize := 10 << 20 // 128 MiB
	//fileSize := 1 << 30 // 128 MiB
	t.Logf("Transferring file size: %d bytes", fileSize)

	t1, t2, stop, _, err := makeConn(0.98, true, t)
	assert.NilError(t, err)
	defer stop()

	sendBuf := make([]byte, fileSize)
	_, err = rand.Read(sendBuf)
	assert.NilError(t, err)

	recvBuf := new(bytes.Buffer)

	var wg sync.WaitGroup
	wg.Add(2)

	start := time.Now()

	go func() {
		defer wg.Done()
		rd := bytes.NewReader(sendBuf)
		if err := chunkedCopy(t1, rd); err != nil {
			t.Errorf("client write failed: %v", err)
		}
		if err := t1.Close(); err != nil {
			t.Errorf("client close failed: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := chunkedCopy(recvBuf, t2); err != nil {
			t.Errorf("server read failed: %v", err)
		}
		if err := t2.Close(); err != nil {
			t.Errorf("server close failed: %v", err)
		}
	}()

	wg.Wait()
	elapsed := time.Since(start)

	// Verify data integrity takes 90% of the test
	//assert.DeepEqual(t, sendBuf, recvBuf.Bytes())
	// or
	/*
		sentHash := sha256.Sum256(sendBuf)
		receivedHash := sha256.Sum256(recvBuf.Bytes())
		assert.Equal(t, sentHash, receivedHash, "data integrity check failed")
	*/

	throughput := float64(fileSize) / elapsed.Seconds() / (1 << 20)
	t.Logf("Transfer completed in %v", elapsed)
	t.Logf("Throughput: %.2f MB/s", throughput)

	if !bytes.Equal(recvBuf.Bytes(), sendBuf) {
		t.Error("transmitted data differs")
	}
}

func chunkedCopy(w io.Writer, r io.Reader) error {
	// TODO (paul): is the chuck size correct?
	b := make([]byte, 1024)
	_, err := io.CopyBuffer(struct{ io.Writer }{w}, struct{ io.Reader }{r}, b)
	return err
}

func BenchmarkHeapPush(b *testing.B) {
	pq := &PriorityQueue{}
	heap.Init(pq)

	for i := 0; i < b.N; i++ {
		heap.Push(pq, &pqItem{priority: uint64(i)})
	}
}

func BenchmarkHeapPop(b *testing.B) {
	pq := &PriorityQueue{}
	heap.Init(pq)
	for i := 0; i < 1000000; i++ {
		heap.Push(pq, &pqItem{priority: uint64(i)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if pq.Len() > 0 {
			heap.Pop(pq)
		}
	}
}

func BenchmarkHeapThroughput(b *testing.B) {
	packetSize := 1500
	numPackets := b.N

	pq := &PriorityQueue{}
	heap.Init(pq)

	startTime := time.Now()
	windowStart := uint64(0) // Expected packet order

	// Simulate receiving packets and pushing them into the heap
	for i := 0; i < numPackets; i++ {
		heap.Push(pq, &pqItem{
			value:    make([]byte, packetSize),
			priority: uint64(i),
		})
	}

	bytesProcessed := 0
	for pq.Len() > 0 {
		// Generate a cryptographically secure random number
		var randByte [8]byte
		_, err := rand.Read(randByte[:]) // Read 8 random bytes
		if err != nil {
			b.Fatalf("Failed to generate random number: %v", err)
		}
		randomFloat := float64(binary.LittleEndian.Uint64(randByte[:])) / (1 << 64) // Convert to [0,1)

		// Introduce 1% probability of popping out of order
		if pq.Len() > 1 && randomFloat < 0.02 {
			// Pop an extra item (out-of-order packet)
			outOfOrderItem := heap.Pop(pq).(*pqItem)
			heap.Push(pq, outOfOrderItem) // Push it back
		}

		item := heap.Pop(pq).(*pqItem)

		// If out of order, push it back and wait for the correct packet
		if item.priority > windowStart {
			heap.Push(pq, item)
			continue
		}

		// Process in-order packet
		bytesProcessed += len(item.value)
		windowStart++ // Move expected window forward
	}

	elapsedTime := time.Since(startTime).Seconds()
	throughputMBps := float64(bytesProcessed) / elapsedTime / 1024 / 1024

	b.ReportMetric(throughputMBps, "MB/sec")
	b.ReportMetric(float64(bytesProcessed)/1024/1024, "MB")
}
