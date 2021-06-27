package channels

import (
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
	"zmap.io/portal/certs"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

func newTestServerConfig(t *testing.T) *transport.ServerConfig {
	keyPair, err := keys.ReadDHKeyFromPEMFile("./testdata/leaf-key.pem")
	assert.NilError(t, err)
	certificate, err := certs.ReadCertificatePEMFile("testdata/leaf.pem")
	assert.NilError(t, err)
	intermediate, err := certs.ReadCertificatePEMFile("testdata/intermediate.pem")
	assert.NilError(t, err)
	return &transport.ServerConfig{
		KeyPair:      keyPair,
		Certificate:  certificate,
		Intermediate: intermediate,
	}
}

func TestMuxer(t *testing.T) {
	logrus.SetLevel(logrus.InfoLevel)
	pktConn, err := net.ListenPacket("udp", "localhost:8888")
	assert.NilError(t, err)
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	server, err := transport.NewServer(udpConn, newTestServerConfig(t))
	assert.NilError(t, err)
	go server.Serve()

	transportConn, err := transport.Dial("udp", udpConn.LocalAddr().String(), nil)
	assert.NilError(t, err)

	assert.NilError(t, transportConn.Handshake())

	serverConn, err := server.AcceptTimeout(time.Minute)
	assert.NilError(t, err)

	mc := NewMuxer(transportConn)
	go mc.Start()

	channel, err := mc.CreateChannel(1 << 8)
	assert.NilError(t, err)

	ms := NewMuxer(serverConn)
	go ms.Start()

	testData := "hi i am some data"

	_, err = channel.Write([]byte(testData))
	assert.NilError(t, err)

	serverChan, err := ms.Accept()
	assert.NilError(t, err)

	buf := make([]byte, len(testData))
	time.Sleep(time.Second)
	bytesRead := 0
	i := 0
	for {
		n, err := serverChan.Read(buf[bytesRead:])
		bytesRead += n
		if err != nil || i > 20 {
			break
		}
		i += 1
		time.Sleep(20 * time.Millisecond)
	}

	assert.Check(t, cmp.Len(testData, bytesRead))
	assert.Equal(t, testData, string(buf))
}

func TestSmallWindow(t *testing.T) {
	logrus.SetLevel(logrus.InfoLevel)
	pktConn, err := net.ListenPacket("udp", "localhost:8889")
	assert.NilError(t, err)
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	server, err := transport.NewServer(udpConn, newTestServerConfig(t))
	assert.NilError(t, err)
	go server.Serve()

	transportConn, err := transport.Dial("udp", udpConn.LocalAddr().String(), nil)
	assert.NilError(t, err)

	assert.NilError(t, transportConn.Handshake())

	serverConn, err := server.AcceptTimeout(time.Minute)
	assert.NilError(t, err)

	mc := NewMuxer(transportConn)
	go mc.Start()

	channel, err := mc.CreateChannel(1 << 7)
	assert.NilError(t, err)

	ms := NewMuxer(serverConn)
	go ms.Start()

	testData := make([]byte, 200)
	for i := range testData {
		testData[i] = []byte{'g', 'h', 'i', 'j', 'k', 'l'}[rand.Intn(6)]
	}

	_, err = channel.Write([]byte(testData))
	assert.NilError(t, err)
	// err = channel.Close()
	assert.NilError(t, err)

	serverChan, err := ms.Accept()
	assert.NilError(t, err)

	buf := make([]byte, len(testData))
	time.Sleep(time.Second)
	bytesRead := 0
	i := 0
	for {
		n, err := serverChan.Read(buf[bytesRead:])
		time.Sleep(20 * time.Millisecond)
		bytesRead += n
		if err != nil || i == 600 {
			logrus.Info(err)
			break
		}
		i += 1
	}
	logrus.Info("I", i)
	assert.Check(t, cmp.Len(testData, bytesRead))
	assert.Equal(t, string(testData), string(buf))
}
