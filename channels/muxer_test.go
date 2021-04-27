package channels

import (
	"net"
	"testing"
	"time"

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
	pktConn, err := net.ListenPacket("udp", "localhost:8888")
	assert.NilError(t, err)
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	server, err := transport.NewServer(udpConn, newTestServerConfig(t))
	assert.NilError(t, err)
	go server.Serve()

	transportConn, err := transport.Dial("udp", udpConn.LocalAddr().String(), nil)
	assert.NilError(t, err)

	serverConn, err := server.AcceptTimeout(time.Minute)
	assert.NilError(t, err)

	m := Muxer{
		underlying: transportConn,
	}
	go m.Start()

	channel, err := m.Accept()
	assert.NilError(t, err)

	ms := Muxer{
		underlying: serverConn,
	}
	go ms.Start()

	testData := "hi I am some written data"

	_, err = channel.Write([]byte(testData))
	assert.NilError(t, err)

	serverChan, err := ms.Accept()
	assert.NilError(t, err)

	buf := make([]byte, len(testData))
	n, err := serverChan.Read(buf)
	assert.NilError(t, err)
	assert.Check(t, cmp.Len(testData, n))
	assert.Check(t, cmp.Equal(testData, string(buf)))
}
