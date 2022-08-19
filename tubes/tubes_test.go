package tubes

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/nettest"
	"gotest.tools/assert"

	"hop.computer/hop/certs"
	"hop.computer/hop/common"
	"hop.computer/hop/keys"
	"hop.computer/hop/transport"
)

func newServerConfig(t *testing.T) (transport.ServerConfig, transport.VerifyConfig) {
	config := transport.ServerConfig{
		HandshakeTimeout: 1 * time.Second,
	}

	config.KeyPair = keys.GenerateNewX25519KeyPair()
	intermediateKeyPair := keys.GenerateNewSigningKeyPair()
	rootKeyPair := keys.GenerateNewSigningKeyPair()

	root, err := certs.SelfSignRoot(certs.SigningIdentity(rootKeyPair), rootKeyPair)
	root.ProvideKey((*[32]byte)(&rootKeyPair.Private))
	assert.NilError(t, err)

	config.Intermediate, err = certs.IssueIntermediate(root, certs.SigningIdentity(intermediateKeyPair))
	config.Intermediate.ProvideKey((*[32]byte)(&intermediateKeyPair.Private))
	assert.NilError(t, err)

	config.Certificate, err = certs.IssueLeaf(config.Intermediate, certs.LeafIdentity(config.KeyPair, certs.DNSName("example.local")))
	assert.NilError(t, err)

	verify := transport.VerifyConfig{
		Store: certs.Store{},
	}
	verify.Store.AddCertificate(root)

	return config, verify
}

func makeTubeConn(t *testing.T) (c1, c2 net.Conn, stop func(), err error) {
	serverUDP, err := net.ListenUDP("udp", nil)
	assert.NilError(t, err)

	serverConfig, verify := newServerConfig(t)
	server, err := transport.NewServer(serverUDP, serverConfig)
	assert.NilError(t, err)

	go server.Serve()

	keypair := keys.GenerateNewX25519KeyPair()
	assert.NilError(t, err)
	leaf, err := certs.SelfSignLeaf(&certs.Identity{
		PublicKey: keypair.Public,
	})
	assert.NilError(t, err)
	clientConfig := transport.ClientConfig{
		Verify:    verify,
		Exchanger: keypair,
		Leaf:      leaf,
	}
	client, err := transport.Dial("udp", serverUDP.LocalAddr().String(), clientConfig)
	assert.NilError(t, err)

	err = client.Handshake()
	assert.NilError(t, err)

	handle, err := server.AcceptTimeout(time.Second)
	assert.NilError(t, err)

	// TODO(hosono) change to reasonable timeouts
	clientMuxer := NewMuxer(client, 2 * time.Second)
	serverMuxer := NewMuxer(handle, 2 * time.Second)
	go func() {
		clientMuxer.Start()
		logrus.Infof("client muxer stopped")
	}()
	go func() {
		serverMuxer.Start()
		logrus.Infof("server muxer stopped")
	}()

	t1, err := clientMuxer.CreateTube(common.ExecTube)
	assert.NilError(t, err)
	t1.WaitForInitiated()
	c1 = net.Conn(t1)

	t2, err := serverMuxer.Accept()
	assert.NilError(t, err)
	t2.WaitForInitiated()
	c2 = net.Conn(t2)

	stop = func() {
		c1.Close()
		c2.Close()
		clientMuxer.Stop()
		serverMuxer.Stop()
		client.Close()
		server.Close()
	}

	return c1, c2, stop, err
}

func TestClose(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	client, server, stop, err := makeTubeConn(t)
	assert.NilError(t, err)

	server.Close()

	b := make([]byte, 1024)
	n, err := client.Read(b)
	assert.DeepEqual(t, n, 0)
	assert.ErrorType(t, err, io.EOF)

	n, err = server.Read(b)
	assert.DeepEqual(t, n, 0)
	assert.ErrorType(t, err, io.EOF)

	stop()
}

func TestTubes(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	mk := nettest.MakePipe(
		func() (c1, c2 net.Conn, stop func(), err error) {
			return makeTubeConn(t)
		})
	nettest.TestConn(t, mk)
}
