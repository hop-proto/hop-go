package transport

import (
	"io"
	"net"
	"testing"
	"time"

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

func makeConn(t *testing.T) (*Client, *Handle, *Server, func(), error) {
	serverUDP, clientUDP := MakeRelaibleUDPConn()

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
	handle, err  := serverConn.AcceptTimeout(time.Second)
	assert.NilError(t, err)

	stop := func() {
		serverConn.CloseSession(handle.sessionID)
		clientConn.Close()
		serverConn.Close()
	}

	return clientConn, handle, serverConn, stop, nil
}

func TestClose(t *testing.T) {
	t.Run("ClientClose", clientClose)
	t.Run("HandleClose", handleClose)
	t.Run("ServerClose", serverClose)

}

// Tests that closing the client connection causes server reads to error
func clientClose(t *testing.T) {
	client, handle, _, stop, err := makeConn(t)
	assert.NilError(t, err)

	client.Close()
	assert.Equal(t, client.closed.IsSet(), true)

	time.Sleep(time.Second)

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

	stop()
}

// Tests that closing the handle causes client reads to error
func handleClose(t *testing.T) {
	client, handle, _, stop, err := makeConn(t)
	assert.NilError(t, err)

	handle.Close()
	assert.Equal(t, handle.IsClosed(), true)

	time.Sleep(time.Second)

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

// Tests that closing the server causes the handle and clients to close
func serverClose(t *testing.T) {
	client, handle, server, stop, err := makeConn(t)
	assert.NilError(t, err)

	server.Close()
	assert.Equal(t, server.closed.IsSet(), true)

	b := make([]byte, 1024)

	// TODO(hosono) maybe this should panic?
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
	c1, c2 := MakeRelaibleUDPConn()
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
		c1, c2, _, stop, err := makeConn(t)
		return c1, c2, stop, err
	}

	makePipe2 := func() (net.Conn, net.Conn, func(), error) {
		c1, c2, _, stop, err := makeConn(t)
		return c2, c1, stop, err
	}

	t.Run("ClientServerConn", func(t *testing.T) {
		mp := nettest.MakePipe(makePipe1)
		nettest.TestConn(t, mp)
	} )

	t.Run("ServerClientConn", func(t *testing.T) {
		mp := nettest.MakePipe(makePipe2)
		nettest.TestConn(t, mp)
	} )
}
