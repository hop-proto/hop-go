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

type UDPOverTCP struct {
	net.TCPConn
}

func (u *UDPOverTCP) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	n, err = u.Write(b)
	return n, 0, err
}

func (u *UDPOverTCP) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	n, err = u.Read(b)
	remoteAddr := net.UDPAddr{
		IP: []byte{1, 2, 3, 4},
		Port: 0,
	}
	return n, 0, 0, &remoteAddr, err
}

// Wrapper around the client nettests
func TestTransportConn(t *testing.T) {
	makePipe := func() (net.Conn, net.Conn, func(), error) {
		// Start server UDP connection
		serverListener, err := net.ListenTCP("tcp", &net.TCPAddr{})
		assert.NilError(t, err)

		clientTCP, err := net.Dial("tcp", serverListener.Addr().String())
		assert.NilError(t, err)

		serverTCP, err := serverListener.AcceptTCP()
		assert.NilError(t, err)

		err = serverListener.Close()
		assert.NilError(t, err)

		// Create new server
		serverUDP := &UDPOverTCP{*serverTCP}
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
		clientNewTCP, ok := clientTCP.(*net.TCPConn)
		if !ok {
			t.Error("Failed to converted clientTCP from net.Conn to net.TCPConn")
		}
		clientUDP := &UDPOverTCP{*clientNewTCP}
		// TODO(hosono) pass in a real address
		remoteAddr := net.UDPAddr{
			IP: []byte{1, 2, 3, 4},
			Port: 0,
		}
		clientConn := NewClient(clientUDP, &remoteAddr, ClientConfig{
			Verify:    *verifyConfig,
			Exchanger: keyPair,
			Leaf:      leaf,
		})

		// Perform Handshake
		err = clientConn.Handshake()
		assert.NilError(t, err)

		// Get handle from server
		handle, err  := serverConn.AcceptTimeout(10 * time.Second)
		assert.NilError(t, err)

		stop := func() {
			serverConn.CloseSession(handle.sessionID)
			clientConn.Close()
			serverConn.Close()
		}

		return clientConn, handle, stop, nil
	}
	var mp = nettest.MakePipe(makePipe)

	reliableUDPMakePipe := func() (net.Conn, net.Conn, func(), error) {
		c1, c2 := MakeRelaibleUDPConn()
		stop := func() {
			c1.Close()
			c2.Close()
		}
		return c1, c2, stop, nil
	}

	mp = nettest.MakePipe(makePipe)
	mp = nettest.MakePipe(reliableUDPMakePipe)
	nettest.TestConn(t, mp)
}
