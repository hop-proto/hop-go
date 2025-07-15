package transport

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

// +checklocksignore
func TestPQNoiseXXHandshake(t *testing.T) {
	var err error
	logrus.SetLevel(logrus.DebugLevel)

	client, server, raddr, clientKeypair, _ := newPQClientAndServerForBench(t)

	client.hs = new(HandshakeState)
	client.hs.duplex.InitializeEmpty()
	client.hs.duplex.Absorb([]byte(PostQuantumProtocolName))

	client.ss = new(SessionState)

	// init kem
	client.hs.kem = new(kemState)
	client.hs.kem.impl = keys.MlKem512
	client.hs.kem.ephemeral, err = keys.MlKem512.GenerateKeypair(rand.Reader)
	assert.Check(t, cmp.Equal(nil, err))
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
	serverHs.kem.static = server.config.KEMKeyPair

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

	// Server Conf // TODO (paul): shall we add a cookie here as long as there is a response here? might need it
	serverBuf = make([]byte, 65535)
	n, err1 = server.writePQServerConf(serverBuf, serverHs)
	_, err2 = client.hs.readPQServerConf(serverBuf[:n])
	assert.NilError(t, err1)
	assert.NilError(t, err2)

	err = client.hs.deriveFinalKeys(&client.ss.clientToServerKey, &client.ss.serverToClientKey)
	assert.NilError(t, err)

	serverSs := server.fetchSessionLocked(serverHs.sessionID)
	err = serverHs.deriveFinalKeys(&serverSs.clientToServerKey, &serverSs.serverToClientKey)
	assert.NilError(t, err)

	// Check final keys
	assert.Check(t, cmp.Equal(client.ss.serverToClientKey, serverSs.serverToClientKey))
	assert.Check(t, cmp.Equal(client.ss.clientToServerKey, serverSs.clientToServerKey))
}

// +checklocksignore
func TestPQNoiseIKHandshake(t *testing.T) {
	var err error
	logrus.SetLevel(logrus.DebugLevel)

	client, server, raddr, clientKeypair, serverStatic := newPQClientAndServerForBench(t)

	client.hs = new(HandshakeState)
	client.hs.duplex.InitializeEmpty()
	client.hs.duplex.Absorb([]byte(PostQuantumHiddenProtocolName))
	client.hs.RekeyFromSqueeze(PostQuantumHiddenProtocolName)

	client.ss = new(SessionState)

	// init kem
	client.hs.kem = new(kemState)
	client.hs.kem.impl = keys.MlKem512
	client.hs.kem.ephemeral, err = keys.MlKem512.GenerateKeypair(rand.Reader)
	assert.NilError(t, err)
	client.hs.leaf, client.hs.intermediate, err = client.prepareCertificates()
	assert.NilError(t, err)
	client.hs.kem.static = *clientKeypair

	client.hs.kem.remoteStatic = *serverStatic

	assert.Check(t, cmp.Equal(nil, err))

	serverHs := new(HandshakeState)

	// init kem
	serverHs.kem = new(kemState)
	serverHs.kem.impl = keys.MlKem512
	serverHs.kem.ephemeral, err = keys.MlKem512.GenerateKeypair(rand.Reader)
	serverHs.kem.static = server.config.KEMKeyPair

	serverHs.remoteAddr = raddr
	serverHs.cookieKey = server.cookieKey
	serverHs.sni = certs.RawStringName("testing")
	client.hs.remoteAddr = raddr
	client.hs.certVerify = &client.config.Verify

	server.createSessionFromHandshakeLocked(serverHs)
	server.setHandshakeState(raddr, serverHs)

	assert.Check(t, cmp.Equal(nil, err))

	// Client Request
	clientBuf := make([]byte, 65535)
	n, err1 := client.hs.writePQClientRequestHidden(clientBuf)
	_, err2 := server.readPQClientRequestHidden(serverHs, clientBuf[:n])
	assert.NilError(t, err1)
	assert.NilError(t, err2)

	// Server Response
	serverBuf := make([]byte, 65535)
	n, err1 = server.writePQServerResponseHidden(serverHs, serverBuf)
	_, err2 = client.hs.readPQServerResponseHidden(serverBuf[:n])
	assert.NilError(t, err1)
	assert.NilError(t, err2)

	err = client.hs.deriveFinalKeys(&client.ss.clientToServerKey, &client.ss.serverToClientKey)
	assert.NilError(t, err)

	serverSs := server.fetchSessionLocked(serverHs.sessionID)
	err = serverHs.deriveFinalKeys(&serverSs.clientToServerKey, &serverSs.serverToClientKey)
	assert.NilError(t, err)

	// Check final keys
	assert.Check(t, cmp.Equal(client.ss.serverToClientKey, serverSs.serverToClientKey))
	assert.Check(t, cmp.Equal(client.ss.clientToServerKey, serverSs.clientToServerKey))
}

func newPQClientAuth(t assert.TestingT, certificate *certs.Certificate) (*keys.KEMKeypair, *certs.Certificate) {
	k, err := keys.MlKem512.GenerateKeypair(rand.Reader)
	assert.NilError(t, err)
	pubKeyBytes := k.Public().Bytes()
	c, err := certs.IssueLeaf(certificate, &certs.Identity{
		PublicKey: pubKeyBytes,
		Names:     []certs.Name{certs.RawStringName("testing")},
	}, certs.PQLeaf)
	assert.NilError(t, err)
	return &k, c
}

func newPQClientAndServerForBench(t assert.TestingT) (*Client, *Server, *net.UDPAddr, *keys.KEMKeypair, *keys.PublicKey) {

	rootKey := keys.GenerateNewSigningKeyPair()
	intermediateKey := keys.GenerateNewSigningKeyPair()

	rootIdentity := certs.Identity{
		PublicKey: rootKey.Public[:],
		Names:     []certs.Name{certs.RawStringName("Root")},
	}

	root, err := certs.SelfSignRoot(&rootIdentity, rootKey)
	root.ProvideKey((*[32]byte)(&rootKey.Private))
	assert.NilError(t, err)

	intermediateIdentity := certs.Identity{
		PublicKey: intermediateKey.Public[:],
		Names:     []certs.Name{certs.RawStringName("Intermediate")},
	}
	intermediate, err := certs.IssueIntermediate(root, &intermediateIdentity)
	intermediate.ProvideKey((*[32]byte)(&intermediateKey.Private))
	assert.NilError(t, err)

	pc, err := net.ListenPacket("udp", "localhost:0")
	assert.NilError(t, err)
	serverConn := pc.(*net.UDPConn)
	serverConfig, verifyConfig, serverPubStatic := newPQTestServerConfig(t, root, intermediate)
	s, err := NewServer(serverConn, *serverConfig)
	assert.NilError(t, err)

	clientStatic, leaf := newPQClientAuth(t, intermediate) // TODO when generating the keys, what do we do with them
	clientConfig := ClientConfig{
		Verify:       *verifyConfig,
		Exchanger:    nil, // TODO when generating the keys, what do we do with them
		Leaf:         leaf,
		Intermediate: intermediate,
	}

	inner, err := net.ListenPacket(udp, ":0")
	assert.NilError(t, err)
	raddr, err := net.ResolveUDPAddr(udp, pc.LocalAddr().String())
	assert.NilError(t, err)
	c, err := NewClient(inner.(*net.UDPConn), raddr, clientConfig), nil

	assert.NilError(t, err)
	return c, s, raddr, clientStatic, serverPubStatic
}

func newPQTestServerConfig(t assert.TestingT, root *certs.Certificate, intermediate *certs.Certificate) (*ServerConfig, *VerifyConfig, *keys.PublicKey) {

	kp, err := keys.MlKem512.GenerateKeypair(rand.Reader)
	assert.NilError(t, err)
	pubKey := kp.Public()

	leafIdentity := certs.Identity{
		PublicKey: pubKey.Bytes(),
		Names:     []certs.Name{certs.RawStringName("testing")},
	}

	c, err := certs.IssueLeaf(intermediate, &leafIdentity, certs.PQLeaf)

	server := ServerConfig{
		KEMKeyPair:       kp,
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
	return &server, &verify, &pubKey
}
