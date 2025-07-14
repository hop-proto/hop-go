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
func TestPQNoiseXXHandshake(t *testing.T) {
	var err error
	logrus.SetLevel(logrus.DebugLevel)

	client, server, raddr, clientKeypair := newPQClientAndServerForBench(t)

	client.hs = new(HandshakeState)
	client.hs.duplex.InitializeEmpty()
	client.hs.duplex.Absorb([]byte(PostQuantumProtocolName))

	client.ss = new(SessionState)

	// init kem
	client.hs.kem = new(kemState)
	client.hs.kem.impl = keys.MlKem512
	client.hs.kem.ephemeral, err = keys.MlKem512.GenerateKeypair(rand.Reader)
	client.hs.leaf, client.hs.intermediate, err = client.prepareCertificates()
	client.hs.kem.static = *clientKeypair

	assert.Check(t, cmp.Equal(nil, err))

	// TODO init a server instance and maybe a client one too
	serverHs := new(HandshakeState)
	serverHs.duplex.InitializeEmpty()
	serverHs.duplex.Absorb([]byte(PostQuantumProtocolName))

	// init kem
	serverHs.kem = new(kemState)
	serverHs.kem.impl = keys.MlKem512
	serverHs.kem.ephemeral, err = keys.MlKem512.GenerateKeypair(rand.Reader)
	serverHs.kem.static = *server.config.KEMKeyPair

	serverHs.remoteAddr = raddr
	serverHs.cookieKey = server.cookieKey
	client.hs.remoteAddr = raddr
	client.hs.certVerify = &client.config.Verify

	server.createSessionFromHandshakeLocked(serverHs)

	assert.Check(t, cmp.Equal(nil, err))

	// Client Hello
	clientBuf := make([]byte, 65535)
	n, err1 := writePQClientHello(client.hs, clientBuf)
	_, err2 := readPQClientHello(serverHs, clientBuf[:n]) // TODO here write the handle client hello which creates a hs state
	assert.NilError(t, err1)
	assert.NilError(t, err2)

	// Server Hello
	serverBuf := make([]byte, 65535)
	n, err1 = writePQServerHello(serverHs, serverBuf)
	_, err2 = readPQServerHello(client.hs, serverBuf[:n])
	assert.NilError(t, err1)
	assert.NilError(t, err2)

	client.hs.RekeyFromSqueeze(PostQuantumProtocolName)

	// Client Ack
	clientBuf = make([]byte, 65535)
	n, err1 = client.hs.writePQClientAck(clientBuf)
	_, serverHs, err2 = server.readPQClientAck(clientBuf[:n], raddr)
	assert.NilError(t, err1)
	assert.NilError(t, err2)

	// Server Auth
	serverBuf = make([]byte, 65535)
	serverHs.sni = certs.RawStringName("testing")
	server.setHandshakeState(raddr, serverHs)

	n, err1 = server.writePQServerAuth(serverBuf, serverHs)
	_, err2 = client.hs.readPQServerAuth(serverBuf[:n])
	assert.NilError(t, err1)
	assert.NilError(t, err2)

	// Client Auth
	clientBuf = make([]byte, 65535)
	n, err1 = client.hs.writePQClientAuth(clientBuf)
	_, serverHs, err2 = server.readPQClientAuth(clientBuf[:n], raddr)

	assert.NilError(t, err1)
	assert.NilError(t, err2)

	// Server Conf
	serverBuf = make([]byte, 65535)
	n, err1 = server.writePQServerConf(serverBuf, serverHs)
	_, err2 = client.hs.readPQServerConf(serverBuf[:n])
	assert.NilError(t, err1)
	assert.NilError(t, err2)

	err = client.hs.deriveFinalKeys(&client.ss.clientToServerKey, &client.ss.serverToClientKey)

	serverSs := server.fetchSessionLocked(serverHs.sessionID)
	err = serverHs.deriveFinalKeys(&serverSs.clientToServerKey, &serverSs.serverToClientKey)
	assert.NilError(t, err)

	// Check final keys
	assert.Check(t, cmp.Equal(client.ss.serverToClientKey, serverSs.serverToClientKey))
	assert.Check(t, cmp.Equal(client.ss.clientToServerKey, serverSs.clientToServerKey))
}

func newPQClientAuth(t assert.TestingT) (*keys.KEMKeypair, *certs.Certificate) {
	k, err := keys.MlKem512.GenerateKeypair(rand.Reader)
	pubKeyBytes := k.Public().Bytes()
	c, err := certs.SelfSignLeaf(&certs.Identity{
		PublicKey: pubKeyBytes,
		Names:     []certs.Name{certs.RawStringName("testing")},
	})
	assert.NilError(t, err)
	return &k, c
}

func newPQClientAndServerForBench(t assert.TestingT) (*Client, *Server, *net.UDPAddr, *keys.KEMKeypair) {

	rootKey := keys.GenerateNewSigningKeyPair()
	intermediateKey := keys.GenerateNewSigningKeyPair()

	rootIdentity := certs.Identity{
		PublicKey: rootKey.Public[:],
		Names:     []certs.Name{certs.RawStringName("Root")},
	}

	root, err := certs.SelfSignRoot(&rootIdentity, rootKey)
	root.ProvideKey((*[32]byte)(&rootKey.Private))

	intermediateIdentity := certs.Identity{
		PublicKey: intermediateKey.Public[:],
		Names:     []certs.Name{certs.RawStringName("Intermediate")},
	}
	intermediate, err := certs.IssueIntermediate(root, &intermediateIdentity)
	intermediate.ProvideKey((*[32]byte)(&intermediateKey.Private))

	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	serverConn := pc.(*net.UDPConn)
	serverConfig, verifyConfig := newPQTestServerConfig(t, root, intermediate)
	s, err := NewServer(serverConn, *serverConfig)
	assert.NilError(t, err)
	go s.Serve()

	clientStatic, leaf := newPQClientAuth(t) // TODO when generating the keys, what do we do with them
	clientConfig := ClientConfig{
		Verify:       *verifyConfig,
		Exchanger:    nil, // TODO when generating the keys, what do we do with them
		Leaf:         leaf,
		Intermediate: intermediate,
		IsPq:         true,
	}

	inner, err := net.ListenPacket(udp, ":0")
	raddr, err := net.ResolveUDPAddr(udp, pc.LocalAddr().String())
	c, err := NewClient(inner.(*net.UDPConn), raddr, clientConfig), nil

	assert.NilError(t, err)
	return c, s, raddr, clientStatic
}

func newPQTestServerConfig(t assert.TestingT, root *certs.Certificate, intermediate *certs.Certificate) (*ServerConfig, *VerifyConfig) {

	kp, err := keys.MlKem512.GenerateKeypair(rand.Reader)
	pubKeyBytes := kp.Public().Bytes()

	leafIdentity := certs.Identity{
		PublicKey: pubKeyBytes,
		Names:     []certs.Name{certs.RawStringName("Server Leaf")},
	}

	c, err := certs.SelfSignLeaf(&leafIdentity)

	server := ServerConfig{
		KEMKeyPair:       &kp,
		Certificate:      c,
		Intermediate:     intermediate,
		HandshakeTimeout: 5 * time.Second,
	}
	verify := VerifyConfig{
		Store: certs.Store{},
	}
	verify.Store.AddCertificate(root)
	verify.Name = certs.RawStringName("testing")

	assert.Check(t, cmp.Equal(nil, err))
	return &server, &verify
}

// +checklocksignore
func TestPQClientServerCompatibilityHandshake(t *testing.T) {
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
func TestPQClientServerHSWithAgent(t *testing.T) {
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
		PublicKey: public[:],
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

func TestPQBufferSizes(t *testing.T) {
	var err error
	short := make([]byte, HeaderLen+4)
	hs := new(HandshakeState)
	hs.kem = new(kemState)
	hs.duplex.InitializeEmpty()
	hs.kem.ephemeral, err = keys.MlKem512.GenerateKeypair(rand.Reader)
	assert.Check(t, cmp.Equal(nil, err))
	n, err := writePQClientHello(hs, short)
	assert.Check(t, cmp.Equal(ErrBufOverflow, err))
	assert.Check(t, cmp.Equal(0, n))
}

func TestPQCookie(t *testing.T) {
	var cookieKey [KeyLen]byte
	_, err := rand.Read(cookieKey[:])
	assert.NilError(t, err)
	hs := HandshakeState{}
	hs.duplex.InitializeEmpty()
	hs.duplex.Absorb([]byte("some data that is longish"))
	hs.dh.ephemeral.Generate()
	_, err = rand.Read(hs.dh.remoteEphemeral[:])
	assert.NilError(t, err)

	oldPrivate := hs.dh.ephemeral.Private

	hs.remoteAddr = &net.UDPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8675,
	}
	hs.cookieKey = cookieKey
	cookie := make([]byte, 2*CookieLen)
	n, err := hs.writeCookie(cookie)
	assert.Check(t, cmp.Equal(CookieLen, n))
	assert.NilError(t, err)

	bytesRead, err := hs.decryptCookie(cookie)
	assert.Check(t, cmp.Equal(CookieLen, bytesRead))
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(oldPrivate, hs.dh.ephemeral.Private))
}
