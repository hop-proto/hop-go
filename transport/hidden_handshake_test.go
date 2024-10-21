package transport

import (
	"context"
	"hop.computer/hop/agent"
	"hop.computer/hop/certs"
	"hop.computer/hop/common"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"go.uber.org/goleak"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"hop.computer/hop/keys"
)

// TODO (paul): similar to the handshake tests -> improve for the hidden handshake specificities

// +checklocksignore
func TestClientServerCompatibilityHiddenHandshake(t *testing.T) {
	defer goleak.VerifyNone(t)
	logrus.SetLevel(logrus.TraceLevel)

	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)

	sc, vc := newTestServerConfig(t)
	s, err := NewServer(pc.(*net.UDPConn), *sc)
	assert.NilError(t, err)
	go s.Serve()

	serverPublicKey, err := keys.ReadDHKeyFromPubFile("testdata/leaf.pub")
	assert.NilError(t, err)

	ckp, leaf := newClientAuth(t)
	clientConfig := ClientConfig{
		Verify:          *vc,
		Exchanger:       ckp,
		Leaf:            leaf,
		ServerPublicKey: serverPublicKey,
	}
	c, err := Dial("udp", s.Addr().String(), clientConfig)
	assert.NilError(t, err)

	_, err = s.AcceptTimeout(time.Millisecond * 100)
	assert.NilError(t, err)

	ss := s.fetchSession(c.ss.sessionID)
	assert.DeepEqual(t, c.ss.sessionID, ss.sessionID)
	var zero [KeyLen]byte
	assert.Check(t, cmp.Equal(c.ss.clientToServerKey, ss.clientToServerKey))
	assert.Check(t, cmp.Equal(c.ss.serverToClientKey, ss.serverToClientKey))
	assert.Check(t, c.ss.clientToServerKey != zero)
	assert.Check(t, c.ss.serverToClientKey != zero)

	assert.NilError(t, s.Close())
	assert.NilError(t, c.Close())
}

// +checklocksignore
func TestClientServerHiddenHSWithAgent(t *testing.T) {
	defer goleak.VerifyNone(t)

	logrus.SetLevel(logrus.DebugLevel)
	// start server
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	udpC := pc.(*net.UDPConn)
	serverConfig, verifyConfig := newTestServerConfig(t)
	s, err := NewServer(udpC, *serverConfig)
	defer func() {
		err := s.Close()
		assert.NilError(t, err)
	}()
	assert.NilError(t, err)
	go s.Serve()

	//start agent and read in key file to it
	keypath := "testdata/leaf-key.pem"
	d := agent.Data{}
	d.Keys = make(map[string]*keys.X25519KeyPair)
	keyPair, err := keys.ReadDHKeyFromPEMFile(keypath)
	d.Keys[keypath] = keyPair
	assert.NilError(t, err)

	as := agent.New(&d)
	address := net.JoinHostPort("localhost", common.DefaultAgentPortString)
	sock, err := net.Listen("tcp", address)
	if err != nil {
		logrus.Fatalf("unable to open tcp socket %s: %s", address, err)
	}
	logrus.Infof("listening on %s", sock.Addr().String())

	httpServer := http.Server{}
	httpServer.Handler = as
	go httpServer.Serve(sock)
	defer httpServer.Close()

	//aconn, err := net.Dial("tcp", sock.Addr().String())
	assert.NilError(t, err)
	logrus.Infof("dialing %s", sock.Addr().String())
	//logrus.Infof("aconn %s", aconn.RemoteAddr().String())

	// Connect to the agent
	ac := agent.Client{
		BaseURL:    sock.Addr().String(),
		HTTPClient: http.DefaultClient,
	}

	keydescr, err := ac.Get(context.Background(), keypath)
	assert.NilError(t, err)
	var public keys.PublicKey
	assert.Check(t, len(keydescr.Public[:]) == 32)
	copy(public[:], keydescr.Public[0:32])

	assert.Check(t, ac.Available(context.Background()))

	bc := &agent.BoundClient{
		C:      &ac,
		Ctx:    context.Background(),
		KeyID:  keypath,
		Public: public[:],
	}

	leaf, err := certs.SelfSignLeaf(&certs.Identity{
		PublicKey: public,
	})

	assert.NilError(t, err)

	serverPublicKey, err := keys.ReadDHKeyFromPubFile("testdata/leaf.pub")
	assert.NilError(t, err)

	c, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{
		Verify:          *verifyConfig,
		Exchanger:       bc,
		Leaf:            leaf,
		ServerPublicKey: serverPublicKey,
	})
	defer func() {
		err := c.Close()
		assert.NilError(t, err)
	}()
	assert.NilError(t, err)
	err = c.Handshake()
	assert.Check(t, err)
	time.Sleep(time.Second)
	ss := s.fetchSession(c.ss.sessionID)
	assert.DeepEqual(t, c.ss.sessionID, ss.sessionID)
	var zero [KeyLen]byte
	assert.Check(t, cmp.Equal(c.ss.clientToServerKey, ss.clientToServerKey))
	assert.Check(t, cmp.Equal(c.ss.serverToClientKey, ss.serverToClientKey))
	assert.Check(t, c.ss.clientToServerKey != zero)
	assert.Check(t, c.ss.serverToClientKey != zero)
}
