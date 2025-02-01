package tubes

import (
	"bytes"
	"crypto/rand"
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

	fileSize := 128 << 20 // 128 MiB
	//fileSize := 1 << 30 // 128 MiB
	t.Logf("Transferring file size: %d bytes", fileSize)

	t1, t2, stop, _, err := makeConn(0.99, true, t)
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
