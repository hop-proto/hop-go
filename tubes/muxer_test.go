package tubes

import (
	"math/rand"
	"net"
	"sync"
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
	pktConn, err := net.ListenPacket("udp", "localhost:8890")
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

	mc := NewMuxer(transportConn, transportConn)
	go mc.Start()

	tube, err := mc.CreateTube(1 << 6)
	assert.NilError(t, err)

	ms := NewMuxer(serverConn, serverConn)
	go ms.Start()

	testData := "hi i am some data"

	go func() {
		_, err = tube.Write([]byte(testData))
		assert.NilError(t, err)
		tube.Close()
	}()

	serverChan, err := ms.Accept()
	assert.NilError(t, err)
	serverChan.Close()

	buf := make([]byte, len(testData))
	time.Sleep(time.Second)
	bytesRead := 0
	logrus.Debug("READING ")
	n, err := serverChan.Read(buf[bytesRead:])
	logrus.Debug("DONE READING ")

	assert.NilError(t, err)
	bytesRead += n
	logrus.Debug("STOPPNG MC")
	mc.Stop()
	logrus.Debug("STOPPNG MS")
	ms.Stop()
	assert.Check(t, cmp.Len(testData, bytesRead))
	assert.Equal(t, testData, string(buf))

}

func TestClosingMuxer(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pktConn, err := net.ListenPacket("udp", "localhost:8891")
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

	mc := NewMuxer(transportConn, transportConn)
	go mc.Start()

	ms := NewMuxer(serverConn, serverConn)
	go ms.Start()

	agc, err := mc.CreateTube(AuthGrantTube)
	assert.NilError(t, err)

	npc, err := mc.CreateTube(NetProxyTube)
	assert.NilError(t, err)

	codex, err := mc.CreateTube(ExecTube)
	assert.NilError(t, err)

	agcs, err := ms.Accept()
	assert.NilError(t, err)

	npcs, err := ms.Accept()
	assert.NilError(t, err)

	codexs, err := ms.Accept()
	assert.NilError(t, err)

	n, e := agc.Write([]byte("sent over agc"))
	assert.NilError(t, e)
	logrus.Infof("Wrote %v bytes", n)
	n, e = npc.Write([]byte("sent over npc"))
	assert.NilError(t, e)
	logrus.Infof("Wrote %v bytes", n)
	n, e = codex.Write([]byte("sent over cod"))
	assert.NilError(t, e)
	logrus.Infof("Wrote %v bytes", n)

	buf1 := make([]byte, 13)
	buf2 := make([]byte, 13)
	buf3 := make([]byte, 13)

	agcs.Read(buf1)
	logrus.Info("agcs recvd: ", string(buf1))
	npcs.Read(buf2)
	logrus.Info("npcs recvd: ", string(buf2))
	codexs.Read(buf3)
	logrus.Info("codexs recvd: ", string(buf3))

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		mc.Stop()
	}()

	ms.Stop()

	wg.Wait()
	logrus.Info("All done!")
}

func TestSmallWindow(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pktConn, err := net.ListenPacket("udp", "localhost:8889")
	assert.NilError(t, err)
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	server, err := transport.NewServer(udpConn, newTestServerConfig(t))
	assert.NilError(t, err)
	go server.Serve()

	transportClient, err := transport.Dial("udp", udpConn.LocalAddr().String(), nil)
	assert.NilError(t, err)

	assert.NilError(t, transportClient.Handshake())

	serverConn, err := server.AcceptTimeout(time.Minute)
	assert.NilError(t, err)

	mc := NewMuxer(transportClient, transportClient)
	go mc.Start()

	ms := NewMuxer(serverConn, serverConn)
	go ms.Start()

	tube, err := mc.CreateTube(1 << 7)
	assert.NilError(t, err)

	testData := make([]byte, 5000)
	for i := range testData {
		testData[i] = []byte{'g', 'h', 'i', 'j', 'k', 'l'}[rand.Intn(6)]
	}

	go func() {
		_, err = tube.Write([]byte(testData))
		assert.NilError(t, err)
		err = tube.Close()
		assert.NilError(t, err)
	}()

	serverChan, err := ms.Accept()
	assert.NilError(t, err)

	buf := make([]byte, len(testData)+2)

	n, err := serverChan.Read(buf)
	serverChan.Close()
	assert.NilError(t, err)
	ms.Stop()
	mc.Stop()
	assert.Check(t, cmp.Len(testData, n))
	assert.Equal(t, string(testData), string(buf[:n]))
}

func TestMultipleChannels(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pktConn, err := net.ListenPacket("udp", "localhost:8894")
	assert.NilError(t, err)
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	server, err := transport.NewServer(udpConn, newTestServerConfig(t))
	assert.NilError(t, err)
	go server.Serve()

	transportClient, err := transport.Dial("udp", udpConn.LocalAddr().String(), nil)
	assert.NilError(t, err)

	assert.NilError(t, transportClient.Handshake())

	serverConn, err := server.AcceptTimeout(time.Minute)
	assert.NilError(t, err)

	mc := NewMuxer(transportClient, transportClient)
	go mc.Start()

	ms := NewMuxer(serverConn, serverConn)
	go ms.Start()

	c1, err := mc.CreateTube(1 << 7)
	assert.NilError(t, err)
	c2, err := ms.CreateTube(1 << 7)
	assert.NilError(t, err)
	c3, err := mc.CreateTube(1 << 7)
	assert.NilError(t, err)

	testData1 := make([]byte, 5000)
	testData2 := make([]byte, 5000)
	testData3 := make([]byte, 5000)
	for i := range testData1 {
		testData1[i] = []byte{'g', 'h', 'i', 'j', 'k', 'l'}[rand.Intn(6)]
	}
	for i := range testData2 {
		testData2[i] = []byte{'g', 'h', 'i', 'j', 'k', 'l'}[rand.Intn(6)]
	}
	for i := range testData3 {
		testData3[i] = []byte{'g', 'h', 'i', 'j', 'k', 'l'}[rand.Intn(6)]
	}

	go func() {
		logrus.Debug("WRITE 1")
		_, err = c1.Write([]byte(testData1))
		assert.NilError(t, err)
		logrus.Debug("WRITE 2")
		_, err = c2.Write([]byte(testData2))
		assert.NilError(t, err)
		logrus.Debug("WRITE 3")
		_, err = c3.Write([]byte(testData3))
		assert.NilError(t, err)
		logrus.Debug("CLOSE 1")
		err = c1.Close()
		assert.NilError(t, err)
		logrus.Debug("CLOSE 2")
		err = c2.Close()
		assert.NilError(t, err)
		logrus.Debug("CLOSE 3")
		err = c3.Close()
		assert.NilError(t, err)
	}()
	logrus.Debug("ACCEPT 1")
	rc1, err := ms.Accept()
	assert.NilError(t, err)
	logrus.Debug("ACCEPT 2")
	rc2, err := mc.Accept()
	assert.NilError(t, err)
	logrus.Debug("ACCEPT 3")
	rc3, err := ms.Accept()
	assert.NilError(t, err)
	logrus.Debug("READ 1")
	buf1 := make([]byte, len(testData1)+2)
	buf2 := make([]byte, len(testData2)+2)
	buf3 := make([]byte, len(testData3)+2)
	rc1.Close()
	n, err := rc1.Read(buf1)
	logrus.Debug("READ 2")
	assert.NilError(t, err)
	assert.Check(t, cmp.Len(testData1, n))
	assert.Equal(t, string(testData1), string(buf1[:n]))
	rc2.Close()
	n, err = rc2.Read(buf2)
	logrus.Debug("READ 3")
	assert.NilError(t, err)
	assert.Check(t, cmp.Len(testData2, n))
	assert.Equal(t, string(testData2), string(buf2[:n]))
	rc3.Close()
	n, err = rc3.Read(buf3)
	logrus.Debug("CHECKING DATA")
	assert.NilError(t, err)
	assert.Check(t, cmp.Len(testData3, n))
	assert.Equal(t, string(testData3), string(buf3[:n]))
	logrus.Debug("STOPPING")
	ms.Stop()
	mc.Stop()
}
