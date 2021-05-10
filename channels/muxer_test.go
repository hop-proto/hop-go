package channels

import (
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
	logrus.SetLevel(logrus.DebugLevel)
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

	mc := NewMuxer(false, transportConn)
	go mc.Start()

	channel, err := mc.CreateChannel()
	assert.NilError(t, err)

	ms := NewMuxer(false, serverConn)
	go ms.Start()

	testData := "hi I am some written data"

	_, err = channel.Write([]byte(testData))
	assert.NilError(t, err)

	serverChan, err := ms.Accept()
	assert.NilError(t, err)

	buf := make([]byte, len(testData))
	var n int
	for {
		n, err = serverChan.Read(buf)
		if err == nil {
			break
		}
	}

	assert.Check(t, cmp.Len(testData, n))
	assert.Check(t, cmp.Equal(testData, string(buf)))
}
