package acme

import (
	"net"
	"strconv"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"hop.computer/hop/certs"
	"hop.computer/hop/config"
	"hop.computer/hop/keys"
)

func createTestServer(t *testing.T, domainName string, keyPair *keys.X25519KeyPair) (*AcmeServer, *certs.Certificate) {
	serverRoot, serverInter, serverLeaf, err := createCertChain(domainName, keyPair)
	assert.NilError(t, err)

	serverConfig := &AcmeServerConfig{
		ServerConfig: &config.ServerConfig{
			Key:                keyPair,
			Certificate:        serverLeaf,
			Intermediate:       serverInter,
			AutoSelfSign:       false,
			ListenAddress:      "localhost:7777",
			HandshakeTimeout:   time.Second,
			DataTimeout:        time.Second,
			CACerts:            []*certs.Certificate{serverRoot, serverInter},
			InsecureSkipVerify: true,
			Users:              []string{AcmeUser},
		},
		SigningCertificate: serverInter,
		log:                logrus.WithField("acmeServer", ""),
	}
	server, err := NewAcmeServer(serverConfig)
	assert.NilError(t, err)
	return server, serverRoot
}

func createTestClient(t *testing.T, server *AcmeServer, serverName string, rootCert *certs.Certificate) *AcmeClient {
	serverListenDomain, p, err := net.SplitHostPort(server.HopServer.ListenAddress().String())
	assert.NilError(t, err)
	port, err := strconv.Atoi(p)
	assert.NilError(t, err)

	username := AcmeUser
	truth := true
	falsey := false
	keyPath := "home/user/.hop/id_hop.pem"
	rootCertPath := "home/user/.hop/root.cert"
	interCertPath := "home/user/.hop/intermediate.cert"
	hc := &config.HostConfigOptional{
		Hostname:             &serverListenDomain,
		Port:                 port,
		User:                 &username,
		AutoSelfSign:         &truth,
		Key:                  &keyPath,
		ServerName:           &serverName,
		CAFiles:              []string{rootCertPath, interCertPath},
		DataTimeout:          int(time.Second),
		RequestAuthorization: &falsey,
	}
	hostConf := hc.Unwrap()
	config := &AcmeClientConfig{
		HostConfig: hostConf,
		Key:        keys.X25519KeyPair{},
		DomainName: "client.com",
	}
	client, err := NewAcmeClient(config)
	assert.NilError(t, err)

	clientKeys := keys.GenerateNewX25519KeyPair()

	rootCertBytes, err := certs.EncodeCertificateToPEM(rootCert)
	assert.NilError(t, err)
	interCertBytes, err := certs.EncodeCertificateToPEM(server.Config.Intermediate)
	assert.NilError(t, err)

	fs := &fstest.MapFS{
		keyPath: &fstest.MapFile{
			Data: []byte(clientKeys.Private.String() + "\n"),
			Mode: 0600,
		},
		rootCertPath: &fstest.MapFile{
			Data: rootCertBytes,
			Mode: 0600,
		},
		interCertPath: &fstest.MapFile{
			Data: interCertBytes,
			Mode: 0600,
		},
	}

	client.HopClient.Fsystem = fs

	assert.NilError(t, err)
	return client
}

func TestAcme(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	serverKeys := keys.GenerateNewX25519KeyPair()
	server, serverRootCert := createTestServer(t, "acme.com", serverKeys)
	logrus.Info("created server")

	client := createTestClient(t, server, "acme.com", serverRootCert)
	logrus.Info("created client")

	go server.Serve()

	err := client.Dial()
	assert.NilError(t, err)
}
