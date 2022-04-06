package transport

import (
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"zmap.io/portal/agent"
	"zmap.io/portal/certs"
	"zmap.io/portal/common"
	"zmap.io/portal/keys"
)

func TestClientServerCompatibilityHandshake(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	udpC := pc.(*net.UDPConn)
	serverConfig, verifyConfig := newTestServerConfig(t)
	s, err := NewServer(udpC, *serverConfig)
	assert.NilError(t, err)
	go s.Serve()
	keyPair, err := keys.ReadDHKeyFromPEMFile("testdata/leaf-key.pem")
	assert.NilError(t, err)
	leaf, err := certs.SelfSignLeaf(&certs.Identity{
		PublicKey: keyPair.Public,
	})
	assert.NilError(t, err)
	c, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{
		Verify:    *verifyConfig,
		Exchanger: keyPair,
		Leaf:      leaf,
	})
	assert.NilError(t, err)
	err = c.Handshake()
	assert.Check(t, err)
	time.Sleep(time.Second)
	ss, ok := s.sessions[c.ss.sessionID]
	assert.Assert(t, ok)
	assert.DeepEqual(t, c.ss.sessionID, ss.sessionID)
	var zero [KeyLen]byte
	assert.Check(t, cmp.Equal(c.ss.clientToServerKey, ss.clientToServerKey))
	assert.Check(t, cmp.Equal(c.ss.serverToClientKey, ss.serverToClientKey))
	assert.Check(t, c.ss.clientToServerKey != zero)
	assert.Check(t, c.ss.serverToClientKey != zero)
}

func TestClientServerHSWithAgent(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	// start server
	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	udpC := pc.(*net.UDPConn)
	serverConfig, verifyConfig := newTestServerConfig(t)
	s, err := NewServer(udpC, *serverConfig)
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
	go http.Serve(sock, as)

	// Connect to the agent
	ac := agent.Client{
		BaseURL:    common.DefaultAgentURL,
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
	c, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{
		Verify:    *verifyConfig,
		Exchanger: bc,
		Leaf:      leaf,
	})
	assert.NilError(t, err)
	err = c.Handshake()
	assert.Check(t, err)
	time.Sleep(time.Second)
	ss, ok := s.sessions[c.ss.sessionID]
	assert.Assert(t, ok)
	assert.DeepEqual(t, c.ss.sessionID, ss.sessionID)
	var zero [KeyLen]byte
	assert.Check(t, cmp.Equal(c.ss.clientToServerKey, ss.clientToServerKey))
	assert.Check(t, cmp.Equal(c.ss.serverToClientKey, ss.serverToClientKey))
	assert.Check(t, c.ss.clientToServerKey != zero)
	assert.Check(t, c.ss.serverToClientKey != zero)
}

func TestBufferSizes(t *testing.T) {
	short := make([]byte, HeaderLen+4)
	hs := new(HandshakeState)
	hs.duplex.InitializeEmpty()
	hs.ephemeral.Generate()
	n, err := writeClientHello(hs, short)
	assert.Check(t, cmp.Equal(ErrBufOverflow, err))
	assert.Check(t, cmp.Equal(0, n))
}

func TestCookie(t *testing.T) {
	var cookieKey [KeyLen]byte
	_, err := rand.Read(cookieKey[:])
	assert.NilError(t, err)
	hs := HandshakeState{}
	hs.duplex.InitializeEmpty()
	hs.duplex.Absorb([]byte("some data that is longish"))
	hs.ephemeral.Generate()
	_, err = rand.Read(hs.remoteEphemeral[:])
	assert.NilError(t, err)

	oldPrivate := hs.ephemeral.Private

	hs.remoteAddr = &net.UDPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8675,
	}
	hs.cookieKey = &cookieKey
	cookie := make([]byte, 2*CookieLen)
	n, err := hs.writeCookie(cookie)
	assert.Check(t, cmp.Equal(CookieLen, n))
	assert.NilError(t, err)

	bytesRead, err := hs.decryptCookie(cookie)
	assert.Check(t, cmp.Equal(CookieLen, bytesRead))
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(oldPrivate, hs.ephemeral.Private))
}
