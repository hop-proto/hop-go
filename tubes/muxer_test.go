package tubes

// TODO(hosono) add these tests back

import (
	//"io"
	//"math/rand"
	//"net"
	"net"
	"sync"
	"testing"

	//"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"

	//"gotest.tools/assert/cmp"
	//"hop.computer/hop/certs"
	//"hop.computer/hop/keys"
	//"hop.computer/hop/common"
	"hop.computer/hop/common"
	"hop.computer/hop/transport"
)

// func newTestServerConfig(t *testing.T) *transport.ServerConfig {
// 	keyPair, err := keys.ReadDHKeyFromPEMFile("./testdata/leaf-key.pem")
// 	assert.NilError(t, err)
// 	certificate, err := certs.ReadCertificatePEMFile("testdata/leaf.pem")
// 	assert.NilError(t, err)
// 	intermediate, err := certs.ReadCertificatePEMFile("testdata/intermediate.pem")
// 	assert.NilError(t, err)
// 	return &transport.ServerConfig{
// 		KeyPair:      keyPair,
// 		Certificate:  certificate,
// 		Intermediate: intermediate,
// 	}
// }

// func getInsecureClientConfig() transport.ClientConfig {
// 	return transport.ClientConfig{
// 		Verify: transport.VerifyConfig{
// 			InsecureSkipVerify: true,
// 		},
// 	}
// }

// func TestMuxer(t *testing.T) {
// 	logrus.SetLevel(logrus.DebugLevel)
// 	pktConn, err := net.ListenPacket("udp", "localhost:8890")
// 	assert.NilError(t, err)
// 	// It's actually a UDP conn
// 	udpConn := pktConn.(*net.UDPConn)
// 	server, err := transport.NewServer(udpConn, newTestServerConfig(t))
// 	assert.NilError(t, err)
// 	go server.Serve()

// 	transportConn, err := transport.Dial("udp", udpConn.LocalAddr().String(), getInsecureClientConfig())
// 	assert.NilError(t, err)

// 	assert.NilError(t, transportConn.Handshake())

// 	serverConn, err := server.AcceptTimeout(time.Minute)
// 	assert.NilError(t, err)

// 	mc := NewMuxer(transportConn, transportConn)
// 	go mc.Start()

// 	tube, err := mc.CreateTube(1 << 6)
// 	assert.NilError(t, err)

// 	ms := NewMuxer(serverConn, serverConn)
// 	go ms.Start()

// 	testData := "hi i am some data"

// 	go func() {
// 		_, err = tube.Write([]byte(testData))
// 		assert.NilError(t, err)
// 		tube.Close()
// 	}()

// 	serverChan, err := ms.Accept()
// 	assert.NilError(t, err)
// 	serverChan.Close()

// 	buf := make([]byte, len(testData))
// 	time.Sleep(time.Second)
// 	bytesRead := 0
// 	logrus.Debug("READING ")
// 	n, err := serverChan.Read(buf[bytesRead:])
// 	logrus.Debug("DONE READING ")

// 	assert.NilError(t, err)
// 	bytesRead += n
// 	logrus.Debug("STOPPNG MC")
// 	mc.Stop()
// 	logrus.Debug("STOPPNG MS")
// 	ms.Stop()
// 	assert.Check(t, cmp.Len(testData, bytesRead))
// 	assert.Equal(t, testData, string(buf))

// }

// func TestClosingMuxer(t *testing.T) {
// 	logrus.SetLevel(logrus.DebugLevel)
// 	pktConn, err := net.ListenPacket("udp", "localhost:8891")
// 	assert.NilError(t, err)
// 	// It's actually a UDP conn
// 	udpConn := pktConn.(*net.UDPConn)
// 	server, err := transport.NewServer(udpConn, newTestServerConfig(t))
// 	assert.NilError(t, err)
// 	go server.Serve()

// 	transportConn, err := transport.Dial("udp", udpConn.LocalAddr().String(), getInsecureClientConfig())
// 	assert.NilError(t, err)

// 	assert.NilError(t, transportConn.Handshake())

// 	serverConn, err := server.AcceptTimeout(time.Minute)
// 	assert.NilError(t, err)

// 	mc := NewMuxer(transportConn, transportConn)
// 	go mc.Start()

// 	ms := NewMuxer(serverConn, serverConn)
// 	go ms.Start()

// 	agc, err := mc.CreateTube(AuthGrantTube)
// 	assert.NilError(t, err)

// 	npc, err := mc.CreateTube(NetProxyTube)
// 	assert.NilError(t, err)

// 	codex, err := mc.CreateTube(ExecTube)
// 	assert.NilError(t, err)

// 	agcs, err := ms.Accept()
// 	assert.NilError(t, err)

// 	npcs, err := ms.Accept()
// 	assert.NilError(t, err)

// 	codexs, err := ms.Accept()
// 	assert.NilError(t, err)

// 	n, e := agc.Write([]byte("sent over agc"))
// 	assert.NilError(t, e)
// 	logrus.Infof("Wrote %v bytes", n)
// 	n, e = npc.Write([]byte("sent over npc"))
// 	assert.NilError(t, e)
// 	logrus.Infof("Wrote %v bytes", n)
// 	n, e = codex.Write([]byte("sent over cod"))
// 	assert.NilError(t, e)
// 	logrus.Infof("Wrote %v bytes", n)

// 	buf1 := make([]byte, 13)
// 	buf2 := make([]byte, 13)
// 	buf3 := make([]byte, 13)

// 	agcs.Read(buf1)
// 	logrus.Info("agcs recvd: ", string(buf1))
// 	npcs.Read(buf2)
// 	logrus.Info("npcs recvd: ", string(buf2))
// 	codexs.Read(buf3)
// 	logrus.Info("codexs recvd: ", string(buf3))

// 	wg := sync.WaitGroup{}
// 	wg.Add(1)

// 	go func() {
// 		defer wg.Done()
// 		mc.Stop()
// 	}()

// 	ms.Stop()

// 	wg.Wait()
// 	logrus.Info("All done!")
// }

// func TestSmallWindow(t *testing.T) {
// 	logrus.SetLevel(logrus.DebugLevel)
// 	pktConn, err := net.ListenPacket("udp", "localhost:8889")
// 	assert.NilError(t, err)
// 	// It's actually a UDP conn
// 	udpConn := pktConn.(*net.UDPConn)
// 	server, err := transport.NewServer(udpConn, newTestServerConfig(t))
// 	assert.NilError(t, err)
// 	go server.Serve()

// 	transportClient, err := transport.Dial("udp", udpConn.LocalAddr().String(), getInsecureClientConfig())
// 	assert.NilError(t, err)

// 	assert.NilError(t, transportClient.Handshake())

// 	serverConn, err := server.AcceptTimeout(time.Minute)
// 	assert.NilError(t, err)

// 	mc := NewMuxer(transportClient, transportClient)
// 	go mc.Start()

// 	ms := NewMuxer(serverConn, serverConn)
// 	go ms.Start()

// 	tube, err := mc.CreateTube(1 << 7)
// 	assert.NilError(t, err)

// 	testData := make([]byte, 5000)
// 	for i := range testData {
// 		testData[i] = []byte{'g', 'h', 'i', 'j', 'k', 'l'}[rand.Intn(6)]
// 	}

// 	go func() {
// 		_, err = tube.Write(testData)
// 		assert.NilError(t, err)
// 		err = tube.Close()
// 		assert.NilError(t, err)
// 	}()

// 	serverChan, err := ms.Accept()
// 	assert.NilError(t, err)

// 	buf := make([]byte, len(testData)+2)

// 	n, err := serverChan.Read(buf)
// 	serverChan.Close()
// 	assert.NilError(t, err)
// 	ms.Stop()
// 	mc.Stop()
// 	assert.Check(t, cmp.Len(testData, n))
// 	assert.Equal(t, string(testData), string(buf[:n]))
// }

// func TestMultipleChannels(t *testing.T) {
// 	logrus.SetLevel(logrus.DebugLevel)
// 	pktConn, err := net.ListenPacket("udp", "localhost:8894")
// 	assert.NilError(t, err)
// 	// It's actually a UDP conn
// 	udpConn := pktConn.(*net.UDPConn)
// 	server, err := transport.NewServer(udpConn, newTestServerConfig(t))
// 	assert.NilError(t, err)
// 	go server.Serve()

// 	transportClient, err := transport.Dial("udp", udpConn.LocalAddr().String(), getInsecureClientConfig())
// 	assert.NilError(t, err)

// 	assert.NilError(t, transportClient.Handshake())

// 	serverConn, err := server.AcceptTimeout(time.Minute)
// 	assert.NilError(t, err)

// 	mc := NewMuxer(transportClient, transportClient)
// 	go mc.Start()

// 	ms := NewMuxer(serverConn, serverConn)
// 	go ms.Start()

// 	c1, err := mc.CreateTube(1 << 7)
// 	assert.NilError(t, err)
// 	c2, err := ms.CreateTube(1 << 7)
// 	assert.NilError(t, err)
// 	c3, err := mc.CreateTube(1 << 7)
// 	assert.NilError(t, err)

// 	testData1 := make([]byte, 5000)
// 	testData2 := make([]byte, 5000)
// 	testData3 := make([]byte, 5000)
// 	for i := range testData1 {
// 		testData1[i] = []byte{'g', 'h', 'i', 'j', 'k', 'l'}[rand.Intn(6)]
// 	}
// 	for i := range testData2 {
// 		testData2[i] = []byte{'g', 'h', 'i', 'j', 'k', 'l'}[rand.Intn(6)]
// 	}
// 	for i := range testData3 {
// 		testData3[i] = []byte{'g', 'h', 'i', 'j', 'k', 'l'}[rand.Intn(6)]
// 	}

// 	go func() {
// 		logrus.Debug("WRITE 1")
// 		_, err = c1.Write(testData1)
// 		assert.NilError(t, err)
// 		logrus.Debug("WRITE 2")
// 		_, err = c2.Write(testData2)
// 		assert.NilError(t, err)
// 		logrus.Debug("WRITE 3")
// 		_, err = c3.Write(testData3)
// 		assert.NilError(t, err)
// 		logrus.Debug("CLOSE 1")
// 		err = c1.Close()
// 		assert.NilError(t, err)
// 		logrus.Debug("CLOSE 2")
// 		err = c2.Close()
// 		assert.NilError(t, err)
// 		logrus.Debug("CLOSE 3")
// 		err = c3.Close()
// 		assert.NilError(t, err)
// 	}()
// 	logrus.Debug("ACCEPT 1")
// 	rc1, err := ms.Accept()
// 	assert.NilError(t, err)
// 	logrus.Debug("ACCEPT 2")
// 	rc2, err := mc.Accept()
// 	assert.NilError(t, err)
// 	logrus.Debug("ACCEPT 3")
// 	rc3, err := ms.Accept()
// 	assert.NilError(t, err)
// 	logrus.Debug("READ 1")
// 	buf1 := make([]byte, len(testData1)+2)
// 	buf2 := make([]byte, len(testData2)+2)
// 	buf3 := make([]byte, len(testData3)+2)
// 	rc1.Close()
// 	n, err := rc1.Read(buf1)
// 	logrus.Debug("READ 2")
// 	assert.NilError(t, err)
// 	assert.Check(t, cmp.Len(testData1, n))
// 	assert.Equal(t, string(testData1), string(buf1[:n]))
// 	rc2.Close()
// 	n, err = rc2.Read(buf2)
// 	logrus.Debug("READ 3")
// 	assert.NilError(t, err)
// 	assert.Check(t, cmp.Len(testData2, n))
// 	assert.Equal(t, string(testData2), string(buf2[:n]))
// 	rc3.Close()
// 	n, err = rc3.Read(buf3)
// 	logrus.Debug("CHECKING DATA")
// 	assert.NilError(t, err)
// 	assert.Check(t, cmp.Len(testData3, n))
// 	assert.Equal(t, string(testData3), string(buf3[:n]))
// 	logrus.Debug("STOPPING")
// 	ms.Stop()
// 	mc.Stop()
// }

func makeMuxers(t *testing.T) (m1, m2 *Muxer, stop func()){
	var c1, c2 transport.MsgConn
	c2Addr, err := net.ResolveUDPAddr("udp", ":7777")
	assert.NilError(t, err)

	c1UDP, err := net.Dial("udp", c2Addr.String())
	assert.NilError(t, err)
	c1 = transport.MakeUDPMsgConn(c1UDP.(*net.UDPConn))

	c2UDP, err := net.DialUDP("udp", c2Addr, c1.LocalAddr().(*net.UDPAddr))
	assert.NilError(t, err)
	c2 = transport.MakeUDPMsgConn(c2UDP)

	m1 = NewMuxer(c1, 0, false, logrus.WithField("muxer", "m1"))
    m1.log.WithField("addr", c1.LocalAddr()).Info("Created")
    m2 = NewMuxer(c2, 0, true, logrus.WithField("muxer", "m2"))
    m2.log.WithField("addr", c2.LocalAddr()).Info("Created")

    go func() {
        e := m1.Start()
        if e != nil {
            logrus.Fatalf("muxer1 error: %v", e)
        }
    }()
    go func() {
        e := m2.Start()
        if e != nil {
            logrus.Fatalf("muxer2 error: %v", e)
        }
    }()

	stop = func() {
		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			m1.Stop()
			wg.Done()
		}()
		go func() {
			m2.Stop()
			wg.Done()
		}()

		wg.Wait()

		c1UDP.Close()
		c2UDP.Close()
	}

	return
}

func manyReliableTubes(t *testing.T) {
	// Each muxer can create exactly 128 tubes.
	// The server creates even numbered tubes. The client creates odd numbered tubes
	m1, m2, stop := makeMuxers(t)
	for i := 1; i < 256; i += 2 {
		logrus.Infof("CreateTube: %d", i)
		tube, err := m1.CreateReliableTube(common.ExecTube)
		assert.NilError(t, err)
		assert.DeepEqual(t, tube.GetID(), byte(i))
	}
	for i := 0; i < 256; i += 2 {
		logrus.Infof("CreateTube: %d", i)
		tube, err := m2.CreateReliableTube(common.ExecTube)
		assert.NilError(t, err)
		assert.DeepEqual(t, tube.GetID(), byte(i))
	}

	tube, err := m1.CreateReliableTube(common.ExecTube)
	assert.ErrorType(t, err, ErrOutOfTubes)
	assert.Assert(t, tube == nil)

	tube, err = m2.CreateReliableTube(common.ExecTube)
	assert.ErrorType(t, err, ErrOutOfTubes)
	assert.Assert(t, tube == nil)

	stop()
}

func manyUnreliableTubes(t *testing.T) {
	// Each muxer can create exactly 128 tubes.
	// The server creates even numbered tubes. The client creates odd numbered tubes
	m1, m2, stop := makeMuxers(t)
	for i := 1; i < 256; i += 2 {
		logrus.Infof("CreateTube: %d", i)
		tube, err := m1.CreateUnreliableTube(common.ExecTube)
		assert.NilError(t, err)
		assert.DeepEqual(t, tube.GetID(), byte(i))
	}
	for i := 0; i < 256; i += 2 {
		logrus.Infof("CreateTube: %d", i)
		tube, err := m2.CreateUnreliableTube(common.ExecTube)
		assert.NilError(t, err)
		assert.DeepEqual(t, tube.GetID(), byte(i))
	}

	tube, err := m1.CreateUnreliableTube(common.ExecTube)
	assert.ErrorType(t, err, ErrOutOfTubes)
	assert.Assert(t, tube == nil)

	tube, err = m2.CreateUnreliableTube(common.ExecTube)
	assert.ErrorType(t, err, ErrOutOfTubes)
	assert.Assert(t, tube == nil)

	stop()
}

func TestMuxer(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)
	t.Run("ManyUnreliableTubes", manyUnreliableTubes)
	t.Run("ManyReliableTubes", manyReliableTubes)
}
