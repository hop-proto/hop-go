package tubes

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
)

func BenchmarkReliable(b *testing.B) {
	logrus.SetOutput(io.Discard)

	t1, t2, stop, _, err := makeConn(1.0, true, b)
	assert.NilError(b, err)
	defer stop()

	wg := sync.WaitGroup{}

	size := 1 << 18
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
			n, err := io.CopyN(t1, bytes.NewReader(sendBuf), int64(size))
			assert.NilError(b, err)
			assert.Equal(b, n, int64(size))
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
