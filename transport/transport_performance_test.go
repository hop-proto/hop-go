package transport

import (
	"crypto/rand"
	"net"
	"testing"

	"gotest.tools/assert"
)

// Change this value to benchmark against larger packets. Leaving it at 1
// roughly tells us the number of nanoseconds required to send a packet, which
// as of 2023-09-08, is ~5000ns.
const benchPacketSize = 1

func newClientAndServerForBench(t assert.TestingT) (*Client, *Server) {
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	serverConn := pc.(*net.UDPConn)
	serverConfig, verifyConfig := newTestServerConfig(t)
	s, err := NewServer(serverConn, *serverConfig)
	assert.NilError(t, err)
	go s.Serve()

	kp, leaf := newClientAuth(t)
	clientConfig := ClientConfig{
		Verify:    *verifyConfig,
		Exchanger: kp,
		Leaf:      leaf,
	}
	c, err := Dial("udp", pc.LocalAddr().String(), clientConfig)
	assert.NilError(t, err)
	return c, s
}

func benchWriter(b *testing.B, writer, reader MsgConn, size int) {
	go func() {
		buf := make([]byte, size)
		for {
			reader.ReadMsg(buf[:])
		}
	}()

	data := make([]byte, size)
	n, err := rand.Read(data[:])
	assert.NilError(b, err)
	assert.Equal(b, len(data), n)
	for i := 0; i < b.N; i++ {
		writer.Write(data[:])
	}
}

func benchReader(b *testing.B, reader, writer MsgConn, size int) {
	go func() {
		data := make([]byte, size)
		n, err := rand.Read(data[:])
		assert.NilError(b, err)
		assert.Equal(b, len(data), n)
		for {
			writer.Write(data[:])
		}
	}()

	buf := make([]byte, size)
	for i := 0; i < b.N; i++ {
		reader.ReadMsg(buf[:])
	}
}

func BenchmarkClientTransportWrite(b *testing.B) {
	c, s := newClientAndServerForBench(b)
	accepted, err := s.Accept()
	assert.NilError(b, err)
	benchWriter(b, c, accepted, benchPacketSize)
}

func BenchmarkServerTransportWrite(b *testing.B) {
	c, s := newClientAndServerForBench(b)
	accepted, err := s.Accept()
	assert.NilError(b, err)
	benchWriter(b, accepted, c, benchPacketSize)
}

func BenchmarkClientTransportRead(b *testing.B) {
	c, s := newClientAndServerForBench(b)
	accepted, err := s.Accept()
	assert.NilError(b, err)

	benchReader(b, c, accepted, benchPacketSize)
}

func BenchmarkServerTransportRead(b *testing.B) {
	c, s := newClientAndServerForBench(b)
	accepted, err := s.Accept()
	assert.NilError(b, err)

	benchReader(b, accepted, c, benchPacketSize)
}
