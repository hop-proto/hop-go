package hoptests

import (
	"net"
	"strconv"
	"testing"
	"testing/fstest"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"zmap.io/portal/agent"
	"zmap.io/portal/certs"
	"zmap.io/portal/config"
	"zmap.io/portal/core"
	"zmap.io/portal/hopclient"
	"zmap.io/portal/hopserver"
	"zmap.io/portal/keys"
	"zmap.io/portal/pkg/thunks"
	"zmap.io/portal/transport"
)

// One hopserver process
type TestServer struct {
	ServerSockPath string

	LeafKeyPair              *keys.X25519KeyPair
	IntermediateKeyPair      *keys.SigningKeyPair
	RootKeyPair              *keys.SigningKeyPair
	Leaf, Intermediate, Root *certs.Certificate
	Store                    certs.Store

	Config          *config.ServerConfig
	TransportConfig *transport.ServerConfig

	AuthorizedKeyFiles map[string][]byte // username to file contents

	FileSystem *fstest.MapFS

	UDPConn   *net.UDPConn
	Transport *transport.Server
	Server    *hopserver.HopServer
}

// One hopclient process
type TestClient struct {
	KeyPair *keys.X25519KeyPair

	AgentClient agent.Client
	Username    string // user it will be authenticating as

	Config        config.ClientConfig
	AuthgrantConn net.Conn
	AgentConn     net.Conn
	Authenticator core.Authenticator // can be nil if want hopclient to make one

	Remote   string // address of server it will be connecting to
	Hostname string

	Client *hopclient.HopClient
}

func NewTestServer(t *testing.T) *TestServer {
	s := new(TestServer)

	var err error
	s.UDPConn, err = net.ListenUDP("udp", nil) // TODO(baumanl): change to just localhost?
	assert.NilError(t, err)

	s.LeafKeyPair = keys.GenerateNewX25519KeyPair()
	s.IntermediateKeyPair = keys.GenerateNewSigningKeyPair()
	s.RootKeyPair = keys.GenerateNewSigningKeyPair()

	s.Root, err = certs.SelfSignRoot(certs.SigningIdentity(s.RootKeyPair), s.RootKeyPair)
	s.Root.ProvideKey((*[32]byte)(&s.RootKeyPair.Private))
	assert.NilError(t, err)

	s.Intermediate, err = certs.IssueIntermediate(s.Root, certs.SigningIdentity(s.IntermediateKeyPair))
	s.Intermediate.ProvideKey((*[32]byte)(&s.IntermediateKeyPair.Private))
	assert.NilError(t, err)

	s.Leaf, err = certs.IssueLeaf(s.Intermediate, certs.LeafIdentity(s.LeafKeyPair, certs.DNSName("example.local")))
	assert.NilError(t, err)

	s.Store = certs.Store{}
	s.Store.AddCertificate(s.Root)

	// s.Config = set to default????

	s.AuthorizedKeyFiles = make(map[string][]byte)
	logrus.Debug("Created new test server...")
	return s
}

// StartTransport starts transport layer server with optional serverconfig (otherwise default)
func (s *TestServer) StartTransport(t *testing.T) {
	var err error
	if s.TransportConfig == nil { // Default
		logrus.Debug("Using default transport config.")
		s.Transport, err = transport.NewServer(s.UDPConn, transport.ServerConfig{
			Certificate:  s.Leaf,
			Intermediate: s.Intermediate,
			KeyPair:      s.LeafKeyPair,
		})
	} else {
		logrus.Debug("Using custom transport config.")
		s.Transport, err = transport.NewServer(s.UDPConn, *s.TransportConfig)
	}
	assert.NilError(t, err)
	logrus.Debugf("Transport server listening on address: %s", s.Transport.ListenAddress().String())
}

// StartHopServer starts hop server with optional config (otherwise default)
func (s *TestServer) StartHopServer(t *testing.T) {
	var err error

	if s.Transport == nil {
		logrus.Debug("Setting up Hop Server with just config.")
		// all certs necessary would need to be loaded into fsystem.
		s.Server, err = hopserver.NewHopServer(s.Config)
	} else {
		logrus.Debug("Setting up Hop Server with provided Transport server.")
		// starts with external transport server
		s.Server, err = hopserver.NewHopServerExt(s.Transport, s.Config)
	}
	assert.NilError(t, err)
	logrus.Debugf("Hop Server running on address: %s", s.Server.ListenAddress().String())

	fs := fstest.MapFS{}
	for user, file := range s.AuthorizedKeyFiles {
		path := "home/" + user + "/.hop/authorized_keys"
		fs[path] = &fstest.MapFile{
			Data: file,
			Mode: 600,
		}
		logrus.Debugf("Wrote authorized keys to: %s", path)
	}
	logrus.Debug("Wrote authorized keys to server filesystem.")

	s.Server.SetFSystem(fs)

	go s.Server.Serve()
}

func NewTestClient(t *testing.T, s *TestServer, username string) *TestClient {
	c := new(TestClient)
	c.KeyPair = keys.GenerateNewX25519KeyPair()
	c.Remote = s.UDPConn.LocalAddr().String()
	h, p, err := net.SplitHostPort(s.UDPConn.LocalAddr().String())
	c.Hostname = h
	assert.NilError(t, err)
	port, err := strconv.Atoi(p)
	assert.NilError(t, err)

	// TODO(baumanl): what should actual default values be here.
	c.Config = config.ClientConfig{
		Hosts: []config.HostConfig{{
			Pattern:      h,
			Hostname:     h,
			Port:         port,
			User:         username,
			AutoSelfSign: config.True,
			Key:          "home/" + username + "/.hop/id_hop.pem",
		}},
	}
	logrus.Debug("Created new test client...")
	return c
}

func (c *TestClient) StartClient(t *testing.T) {
	var err error
	c.Client, err = hopclient.NewHopClient(&c.Config, c.Hostname)
	assert.NilError(t, err)
	if c.Authenticator != nil {
		c.Client.DialExternalAuthenticator(c.Remote, c.Authenticator)
	}
	if c.AgentConn != nil || c.AuthgrantConn == nil {
		c.Client.DialExternalConn(c.AgentConn, c.AuthgrantConn)
	}
}

func AddClientToAuthorizedKeys(t *testing.T, s *TestServer, c *TestClient) {
	ak := s.AuthorizedKeyFiles[c.Username]
	s.AuthorizedKeyFiles[c.Username] = append(ak, []byte(c.KeyPair.Public.String())...)
}

func (s *TestServer) ChainAuthenticator(t *testing.T, clientKey *keys.X25519KeyPair) core.Authenticator {
	leaf, err := certs.SelfSignLeaf(&certs.Identity{
		PublicKey: clientKey.Public,
	})
	assert.NilError(t, err)
	return core.InMemoryAuthenticator{
		X25519KeyPair: clientKey,
		Leaf:          leaf,
		VerifyConfig: transport.VerifyConfig{
			Store: s.Store,
		},
	}
}

func TestHopClientExtAuth(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	thunks.SetUpTest()
	t.Run("connect", func(t *testing.T) {
		// Create the basic Client and Server
		s := NewTestServer(t)

		c := NewTestClient(t, s, "username")

		// Modify authentication details
		AddClientToAuthorizedKeys(t, s, c)

		s.StartTransport(t)
		s.StartHopServer(t)

		c.Authenticator = s.ChainAuthenticator(t, c.KeyPair)

		c.StartClient(t)
	})
}
