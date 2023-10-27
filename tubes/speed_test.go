package tubes

import (
	"crypto/rand"
	"io"
	"sync"
	"testing"

	_ "net/http/pprof"
	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
)

func BenchmarkReliable(b *testing.B) {
	logrus.SetOutput(io.Discard)

	t1, t2, stop, _, err := makeConn(1.0, true, b)
	assert.NilError(b, err)
	defer stop()

	wg := sync.WaitGroup{}
	wg.Add(1)

	size := 1 << 22
	b.ReportAllocs()
	recvBuf := make([]byte, size)
	sendBuf := make([]byte, size)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = rand.Read(sendBuf)
		assert.NilError(b,err)

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
	
		assert.DeepEqual(b, sendBuf, recvBuf)
	}
	b.SetBytes(int64(size))
}
