package transport

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"go.uber.org/goleak"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"hop.computer/hop/agent"
	"hop.computer/hop/certs"
	"hop.computer/hop/common"
	"hop.computer/hop/keys"
)

func TestClientServerCompatibilityHiddenHandshake(t *testing.T) {
	defer goleak.VerifyNone(t)
	logrus.SetLevel(logrus.TraceLevel)

	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)

	sc, vc := newTestServerConfig(t)
	s, err := NewServer(pc.(*net.UDPConn), *sc)
	assert.NilError(t, err)
	go s.Serve()

	serverPublicKey, err := keys.ReadKEMKeyFromPubFile("testdata/kem_hop.pub")
	assert.NilError(t, err)

	ckp, leaf := newClientAuth(t)
	clientConfig := ClientConfig{
		Verify:       *vc,
		Exchanger:    ckp,
		Leaf:         leaf,
		ServerKEMKey: serverPublicKey,
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
	assert.Equal(t, c.ss.isHiddenHS, true)
	assert.Equal(t, ss.isHiddenHS, true)

	assert.NilError(t, s.Close())
	assert.NilError(t, c.Close())
}

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

	httpServer := http.Server{ReadTimeout: 1 * time.Second}
	httpServer.Handler = as
	go httpServer.Serve(sock)
	defer httpServer.Close()

	assert.NilError(t, err)
	logrus.Infof("dialing %s", sock.Addr().String())

	// Connect to the agent
	ac := agent.Client{
		BaseURL:    sock.Addr().String(),
		HTTPClient: http.DefaultClient,
	}

	keydescr, err := ac.Get(context.Background(), keypath)
	assert.NilError(t, err)
	var public keys.DHPublicKey
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

	// Hidden mode serverPublic key reading
	serverKey, err := keys.ReadKEMKeyFromPubFile("testdata/kem_hop.pub")
	assert.NilError(t, err)

	// adding the serverPublicKey to the client config enabling the hiddenHS
	c, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{
		Verify:       *verifyConfig,
		Exchanger:    bc,
		Leaf:         leaf,
		ServerKEMKey: serverKey,
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
	assert.Equal(t, c.ss.isHiddenHS, true)
	assert.Equal(t, ss.isHiddenHS, true)

	assert.NilError(t, s.Close())
	assert.NilError(t, c.Close())
}

func TestClientHelloHiddenLength(t *testing.T) {
	buf := make([]byte, 65535)
	hs := new(HandshakeState)
	hs.dh = new(dhState)
	hs.duplex.InitializeEmpty()
	hs.dh.ephemeral.Generate()
	hs.RekeyFromSqueeze(HiddenProtocolName)

	keyPair := keys.X25519KeyPair{}
	keyPair.Generate()
	hs.dh.static = &keyPair

	leaf, err := certs.ReadCertificatePEMFile("testdata/leaf.pem")
	assert.NilError(t, err)
	intermediate, err := certs.ReadCertificatePEMFile("testdata/intermediate.pem")
	assert.NilError(t, err)
	hs.leaf, err = leaf.Marshal()
	assert.NilError(t, err)
	hs.intermediate, err = intermediate.Marshal()
	assert.NilError(t, err)
	encCertLen := EncryptedCertificatesLength(hs.leaf[:], hs.intermediate[:])

	expectedLength := HeaderLen + DHLen + encCertLen + MacLen + TimestampLen + MacLen

	currentLength, err := hs.writeClientRequestHidden(buf, &keyPair.Public)
	assert.Check(t, cmp.Equal(expectedLength, currentLength))
	assert.NilError(t, err)
}

// This test stands for being sure that an HS without server public key
// does not go through a hidden HS
func TestClientServerHiddenHandshakeWithoutStaticKey(t *testing.T) {
	defer goleak.VerifyNone(t)
	logrus.SetLevel(logrus.TraceLevel)

	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)

	sc, vc := newTestServerConfig(t)
	s, err := NewServer(pc.(*net.UDPConn), *sc)
	assert.NilError(t, err)
	go s.Serve()

	// initialisation of a ClientConfig without the serverPublic key to go for a discoverable HS
	ckp, leaf := newClientAuth(t)
	clientConfig := ClientConfig{
		Verify:    *vc,
		Exchanger: ckp,
		Leaf:      leaf,
	}
	c, err := Dial("udp", s.Addr().String(), clientConfig)
	assert.NilError(t, err)

	_, err = s.AcceptTimeout(time.Millisecond * 100)
	assert.NilError(t, err)

	ss := s.fetchSession(c.ss.sessionID)
	assert.Equal(t, c.ss.isHiddenHS, false)
	assert.Equal(t, ss.isHiddenHS, false)

	assert.NilError(t, s.Close())
	assert.NilError(t, c.Close())
}

// TODO (paul): write a test to ensure the multiple vhosts in hidden mode
