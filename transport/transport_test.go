package transport

import (
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

// Wrapper around the client nettests
func DontTestTransportConn(t *testing.T) {
	makePipe := func() (net.Conn, net.Conn, func(), error) {

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

		return clientConn, handle, stop, nil
	}

	makeReliableUDPPipe := func() (net.Conn, net.Conn, func(), error) {
		c1, c2 := MakeRelaibleUDPConn()
		stop := func() {
			c1.Close()
			c2.Close()
		}
		return c1, c2, stop, nil
	}

	var mp = nettest.MakePipe(makePipe)
	mp = nettest.MakePipe(makeReliableUDPPipe)
	mp = nettest.MakePipe(makePipe)

	nettest.TestConn(t, mp)
}
