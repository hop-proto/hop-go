package benchmarks

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"

	"gotest.tools/assert"
)

func measureThroughput(b *testing.B, w io.Writer, r io.Reader) {
	wg := &sync.WaitGroup{}
	wg.Add(2)

	b.ResetTimer()

	go func() {
		defer wg.Done()
		buf := make([]byte, b.N)
		n, err := w.Write(buf)
		assert.NilError(b, err)
		assert.Equal(b, n, len(buf))
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, b.N)
		nread := 0
		for nread < len(buf) {
			n, err := r.Read(buf)
			assert.NilError(b, err)
			nread += n
		}
	}()
	wg.Wait()

	b.ReportMetric(float64(b.N)/float64(b.Elapsed().Seconds()), "bytes/secs")
}

func BenchmarkTCP(b *testing.B) {
	listener, err := net.ListenTCP("tcp", nil)
	assert.NilError(b, err)

	c1, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	assert.NilError(b, err)

	c2, err := listener.AcceptTCP()

	measureThroughput(b, c1, c2)

}

func BenchmarkTLS(b *testing.B) {
	l, err := net.ListenTCP("tcp", nil)

	cert := tls.Certificate{}

	config := tls.Config{}

	assert.NilError(b, err)
	listener := tls.NewListener(l, nil)

	c1, err := tls.Dial("tcp", listener.Addr().String(), nil)
	assert.NilError(b, err)

	c2, err := listener.Accept()
	assert.NilError(b, err)

	measureThroughput(b, c1, c2)
}
