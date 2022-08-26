package transport

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/nettest"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/kravatte"
)

func TestTransportAEAD(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	sanse, err := kravatte.NewSANSE(key[:])
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(sanse.Overhead(), TagLen))
}

// fakeUDP is true to use the in memory ReliableUDP connection and false to use
// UDP on the loopback interface
func makeConn(t *testing.T, fakeUDP bool) (*Client, *Handle, *Server, func(), error) {
	logrus.SetLevel(logrus.DebugLevel)

	var serverUDP UDPLike
	var clientUDP UDPLike
	if fakeUDP {
		serverUDP, clientUDP = MakeReliableUDPConn(false)
	} else {
		serverPkt, err := net.ListenPacket("udp", "localhost:7777")
		assert.NilError(t, err)
		serverUDP = serverPkt.(*net.UDPConn)
		clientUDP, err = net.DialUDP("udp", nil, serverUDP.LocalAddr().(*net.UDPAddr))
		assert.NilError(t, err)
	}

	// Create new server
	serverConfig, verifyConfig := newTestServerConfig(t)
	serverConn, err := NewServer(serverUDP, *serverConfig)
	assert.NilError(t, err)
	go serverConn.Serve()

	// Set up client info
	keyPair, err := keys.ReadDHKeyFromPEMFile("testdata/leaf-key.pem")
	assert.NilError(t, err)
	leaf, err := certs.SelfSignLeaf(&certs.Identity{
		PublicKey: keyPair.Public,
	})
	assert.NilError(t, err)

	// Dial the server
	clientConn := NewClient(clientUDP, nil, ClientConfig{
		Verify:    *verifyConfig,
		Exchanger: keyPair,
		Leaf:      leaf,
	})

	// Perform Handshake
	err = clientConn.Handshake()
	assert.NilError(t, err)

	// Get handle from server
	handle, err := serverConn.AcceptTimeout(time.Second)
	assert.NilError(t, err)

	stop := func() {
		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			defer wg.Done()
			serverConn.CloseSession(handle.ss.sessionID)
		}()
		go func() {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			clientConn.Close()
		}()
		serverConn.Close()
	}

	return clientConn, handle, serverConn, stop, nil
}

func TestClose(t *testing.T) {
	t.Run("ClientClose", clientClose)
	t.Run("HandleClose", handleClose)
	t.Run("ServerClose", serverClose)
	t.Run("ClientHandleBothClose", bothClose)
	t.Run("AllClose", allClose)
}

func checkEOFReads(t *testing.T, client *Client, handle *Handle) {
	time.Sleep(100 * time.Millisecond)

	b := make([]byte, 1024)

	n, err := client.Read(b)
	assert.ErrorType(t, err, io.EOF)
	assert.Equal(t, n, 0)

	n, err = client.ReadMsg(b)
	assert.ErrorType(t, err, io.EOF)
	assert.Equal(t, n, 0)

	n, err = handle.Read(b)
	assert.ErrorType(t, err, io.EOF)
	assert.Equal(t, n, 0)

	n, err = handle.ReadMsg(b)
	assert.ErrorType(t, err, io.EOF)
	assert.Equal(t, n, 0)
}

// Tests that closing the client connection causes server reads to error
func clientClose(t *testing.T) {
	client, handle, _, stop, err := makeConn(t, false)
	assert.NilError(t, err)

	err = client.Close()
	assert.NilError(t, err)
	assert.DeepEqual(t, client.state, closed)

	checkEOFReads(t, client, handle)

	stop()
}

// Tests that closing the handle causes client reads to error
func handleClose(t *testing.T) {
	client, handle, _, stop, err := makeConn(t, false)
	assert.NilError(t, err)

	done := make(chan struct{})

	go func() {
		time.Sleep(100 * time.Millisecond)
		err := client.Close()
		assert.NilError(t, err)
		done <- struct{}{}
	}()

	err = handle.Close()
	assert.NilError(t, err)
	assert.Equal(t, handle.IsClosed(), true)

	<-done

	checkEOFReads(t, client, handle)

	stop()
}

func bothClose(t *testing.T) {
	client, handle, _, stop, err := makeConn(t, false)
	assert.NilError(t, err)

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		err := client.Close()
		assert.NilError(t, err)
	}()

	go func() {
		defer wg.Done()
		err := handle.Close()
		assert.NilError(t, err)
	}()

	wg.Wait()

	assert.Equal(t, client.IsClosed(), true)
	assert.Equal(t, handle.IsClosed(), true)

	checkEOFReads(t, client, handle)

	stop()
}

func allClose(t *testing.T) {
	client, handle, server, stop, err := makeConn(t, false)
	assert.NilError(t, err)

	wg := sync.WaitGroup{}
	wg.Add(3)

	go func() {
		defer wg.Done()
		err := client.Close()
		assert.NilError(t, err)
	}()

	go func() {
		defer wg.Done()
		handle.Close()
	}()

	go func() {
		defer wg.Done()
		err := server.Close()
		assert.NilError(t, err)
	}()

	wg.Wait()

	assert.Equal(t, client.IsClosed(), true)
	assert.Equal(t, handle.IsClosed(), true)
	assert.Equal(t, server.closed.Load(), true)

	checkEOFReads(t, client, handle)

	stop()
}

// Tests that closing the server causes the handle and clients to close
func serverClose(t *testing.T) {
	client, handle, server, stop, err := makeConn(t, false)
	assert.NilError(t, err)

	done := make(chan struct{})

	go func() {
		time.Sleep(100 * time.Millisecond)
		err := client.Close()
		assert.NilError(t, err)
		done <- struct{}{}
	}()

	err = server.Close()
	assert.NilError(t, err)
	assert.Equal(t, server.closed.Load(), true)

	<-done

	b := make([]byte, 1024)

	n, err := handle.Read(b)
	assert.ErrorType(t, err, io.EOF)
	assert.Equal(t, n, 0)

	n, err = handle.ReadMsg(b)
	assert.ErrorType(t, err, io.EOF)
	assert.Equal(t, n, 0)

	n, err = client.Read(b)
	assert.ErrorType(t, err, io.EOF)
	assert.Equal(t, n, 0)

	n, err = client.ReadMsg(b)
	assert.ErrorType(t, err, io.EOF)
	assert.Equal(t, n, 0)

	stop()
}

func makeReliableUDPPipe() (net.Conn, net.Conn, func(), error) {
	c1, c2 := MakeReliableUDPConn(true)
	stop := func() {
		c1.Close()
		c2.Close()
	}
	return c1, c2, stop, nil
}

// This test only works if closing one side of reliable UDP causes
// the other side to return EOF on reads. This behavior prevents us from
// testing the closing behavior of Client and Server connections.
func DontTestReliableUDP(t *testing.T) {
	mp := nettest.MakePipe(makeReliableUDPPipe)
	nettest.TestConn(t, mp)
}

// Wrapper around the client nettests
func TestTransportConn(t *testing.T) {
	makePipe1 := func() (net.Conn, net.Conn, func(), error) {
		c1, c2, _, stop, err := makeConn(t, true)
		return c1, c2, stop, err
	}

	makePipe2 := func() (net.Conn, net.Conn, func(), error) {
		c1, c2, _, stop, err := makeConn(t, true)
		return c2, c1, stop, err
	}

	t.Run("ClientServerConn", func(t *testing.T) {
		mp := nettest.MakePipe(makePipe1)
		nettest.TestConn(t, mp)
	})

	t.Run("ServerClientConn", func(t *testing.T) {
		mp := nettest.MakePipe(makePipe2)
		nettest.TestConn(t, mp)
	})
}
