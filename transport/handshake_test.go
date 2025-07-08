package transport

import (
	"context"
	"crypto/rand"
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

// +checklocksignore
func TestClientServerCompatibilityHandshake(t *testing.T) {
	defer goleak.VerifyNone(t)
	logrus.SetLevel(logrus.TraceLevel)

	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)

	sc, vc := newTestServerConfig(t)
	s, err := NewServer(pc.(*net.UDPConn), *sc)
	assert.NilError(t, err)
	go s.Serve()

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
	assert.DeepEqual(t, c.ss.sessionID, ss.sessionID)
	var zero [KeyLen]byte
	assert.Check(t, cmp.Equal(c.ss.clientToServerKey, ss.clientToServerKey))
	assert.Check(t, cmp.Equal(c.ss.serverToClientKey, ss.serverToClientKey))
	assert.Check(t, c.ss.clientToServerKey != zero)
	assert.Check(t, c.ss.serverToClientKey != zero)

	//assert.Equal(t, c.LocalAddr().String(), h.RemoteAddr().String())
	//assert.Equal(t, c.RemoteAddr().String(), h.LocalAddr().String())

	assert.NilError(t, s.Close())
	assert.NilError(t, c.Close())
}

// +checklocksignore
func TestClientServerHSWithAgent(t *testing.T) {
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
	c, err := Dial("udp", pc.LocalAddr().String(), ClientConfig{
		Verify:    *verifyConfig,
		Exchanger: bc,
		Leaf:      leaf,
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

func TestBufferSizes(t *testing.T) {
	short := make([]byte, HeaderLen+4)
	hs := new(HandshakeState)
	hs.dh.duplex.InitializeEmpty()
	hs.dh.ephemeral.Generate()
	n, err := writeClientHello(hs, short)
	assert.Check(t, cmp.Equal(ErrBufOverflow, err))
	assert.Check(t, cmp.Equal(0, n))
}

func TestCookie(t *testing.T) {
	var cookieKey [KeyLen]byte
	_, err := rand.Read(cookieKey[:])
	assert.NilError(t, err)
	hs := HandshakeState{}
	hs.dh.duplex.InitializeEmpty()
	hs.dh.duplex.Absorb([]byte("some data that is longish"))
	hs.dh.ephemeral.Generate()
	_, err = rand.Read(hs.dh.remoteEphemeral[:])
	assert.NilError(t, err)

	oldPrivate := hs.dh.ephemeral.Private

	hs.remoteAddr = &net.UDPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8675,
	}
	hs.dh.cookieKey = cookieKey
	cookie := make([]byte, 2*CookieLen)
	n, err := hs.writeCookie(cookie)
	assert.Check(t, cmp.Equal(CookieLen, n))
	assert.NilError(t, err)

	bytesRead, err := hs.decryptCookie(cookie)
	assert.Check(t, cmp.Equal(CookieLen, bytesRead))
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(oldPrivate, hs.dh.ephemeral.Private))
}
