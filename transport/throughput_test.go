package transport

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"testing"

	"gotest.tools/assert"

	"github.com/sirupsen/logrus"
)

func measureThroughput(b *testing.B, w net.Conn, r net.Conn) {
	var nBytes int64 = 10 << 30 // 10 GiB

	b.ResetTimer()

	// Copy from randomness into writer
	go func() {
		_, err := io.Copy(w, rand.New(rand.NewSource(0)))
		// The copy ends when w is closed, which should cause an error
		assert.Assert(b, err != nil)
	}()

	// Copy from reader to /dev/null
	defer r.Close()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	bufNull := bufio.NewWriter(null)
	assert.NilError(b, err)
	_, err = io.CopyN(bufNull, r, nBytes)
	assert.NilError(b, err)

	// Close the writer to end copying
	err = w.Close()
	assert.NilError(b, err)

	bytesPerSecs := float64(nBytes) / b.Elapsed().Seconds()
	b.ReportMetric(bytesPerSecs/(1<<20), "MiB/secs")
}

func BenchmarkTCP(b *testing.B) {
	listener, err := net.ListenTCP("tcp", nil)
	assert.NilError(b, err)

	c1, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	assert.NilError(b, err)

	c2, err := listener.AcceptTCP()
	assert.NilError(b, err)

	measureThroughput(b, c1, c2)
}

func BenchmarkTLS(b *testing.B) {
	// Create Server
	l, err := net.ListenTCP("tcp", nil)
	assert.NilError(b, err)

	cert, err := tls.LoadX509KeyPair("testdata/localhost.crt", "testdata/localhost.key")
	assert.NilError(b, err)

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	listener := tls.NewListener(l, serverConfig)
	defer listener.Close()

	// Create Client
	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	var c1 *tls.Conn
	ch := make(chan struct{})
	go func() {
		addr := "localhost:" + fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
		c1, err = tls.Dial("tcp", addr, clientConfig)
		assert.NilError(b, err)
		ch <- struct{}{}
	}()
	c2, err := listener.Accept()
	assert.NilError(b, err)

	// Need to write one byte. Otherwise, the server never completes the handshake
	c2.Write([]byte{0})

	// Wait for Dial to finish
	<-ch

	measureThroughput(b, c1, c2)
}

func BenchmarkUDP(b *testing.B) {
	pktListener, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(b, err)

	c1, err := net.Dial("udp", pktListener.LocalAddr().String())
	assert.NilError(b, err)

	pktListener.Close()
	c2, err := net.DialUDP("udp", pktListener.LocalAddr().(*net.UDPAddr), c1.LocalAddr().(*net.UDPAddr))
	assert.NilError(b, err)

	measureThroughput(b, c1, c2)
}

func BenchmarkHop(b *testing.B) {
	c, h, _, stop, _, err := makeConn(b)
	assert.NilError(b, err)

	// Set a high log level so we don't need to print to the console
	logrus.SetLevel(logrus.PanicLevel)

	measureThroughput(b, c, h)
	stop()
}
