package hoptests

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"

	"zmap.io/portal/agent"
	"zmap.io/portal/certs"
	"zmap.io/portal/common"
	"zmap.io/portal/config"
	"zmap.io/portal/core"
	"zmap.io/portal/hopclient"
	"zmap.io/portal/hopserver"
	"zmap.io/portal/keys"
	"zmap.io/portal/pkg/thunks"
	"zmap.io/portal/transport"
)

type TestAgent struct {
	Data *agent.Data // map string (keypath) -> keys

	Listener net.Listener
	Agent    agent.Server
}

// One hopserver process
type TestServer struct {
	LeafKeyPair              *keys.X25519KeyPair
	IntermediateKeyPair      *keys.SigningKeyPair
	RootKeyPair              *keys.SigningKeyPair
	Leaf, Intermediate, Root *certs.Certificate
	Store                    certs.Store

	Config          *config.ServerConfig
	TransportConfig *transport.ServerConfig

	AuthorizedKeyFiles map[string][]byte // username to file contents
	FileSystem         *fstest.MapFS

	UDPConn   *net.UDPConn
	Transport *transport.Server
	Server    *hopserver.HopServer
}

// One hopclient process
type TestClient struct {
	KeyPair *keys.X25519KeyPair

	Config   config.ClientConfig
	Username string // user it will be authenticating as
	Remote   string // address of server it will be connecting to
	Hostname string

	AuthgrantConn net.Conn
	AgentConn     net.Conn

	Authenticator core.Authenticator // can be nil if want hopclient to make one

	FileSystem *fstest.MapFS
	Client     *hopclient.HopClient
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

	s.Config = &config.ServerConfig{}
	s.FileSystem = &fstest.MapFS{}

	s.AuthorizedKeyFiles = make(map[string][]byte)
	logrus.Info("Created new test server...")
	return s
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

func (s *TestServer) AddClientToAuthorizedKeys(t *testing.T, c *TestClient) {
	logrus.Info("adding key for ", c.Username)
	ak := s.AuthorizedKeyFiles[c.Username]
	s.AuthorizedKeyFiles[c.Username] = append(ak, []byte(c.KeyPair.Public.String())...)
}

// StartTransport starts transport layer server with optional serverconfig (otherwise default)
func (s *TestServer) StartTransport(t *testing.T) {
	var err error
	if s.TransportConfig == nil { // Default
		logrus.Info("Using default transport config.")
		s.Transport, err = transport.NewServer(s.UDPConn, transport.ServerConfig{
			Certificate:  s.Leaf,
			Intermediate: s.Intermediate,
			KeyPair:      s.LeafKeyPair,
		})
	} else {
		logrus.Info("Using custom transport config.")
		s.Transport, err = transport.NewServer(s.UDPConn, *s.TransportConfig)
	}
	assert.NilError(t, err)
	logrus.Infof("Transport server listening on address: %s", s.Transport.ListenAddress().String())
}

// StartHopServer starts hop server with optional config (otherwise default)
func (s *TestServer) StartHopServer(t *testing.T) {
	var err error

	s.Server.SetFSystem(*s.FileSystem)

	if s.Transport == nil {
		logrus.Info("Setting up Hop Server with just config.")
		// all certs necessary need to be loaded into fsystem. (not currently implemented)
		s.Server, err = hopserver.NewHopServer(s.Config)
	} else {
		logrus.Info("Setting up Hop Server with provided Transport server.")
		// starts with external transport server
		s.Server, err = hopserver.NewHopServerExt(s.Transport, s.Config)
	}
	assert.NilError(t, err)
	logrus.Infof("Hop Server running on address: %s", s.Server.ListenAddress().String())

	for user, file := range s.AuthorizedKeyFiles {
		path := "home/" + user + "/.hop/authorized_keys"
		(*s.FileSystem)[path] = &fstest.MapFile{
			Data: file,
			Mode: 600,
		}
		logrus.Infof("Wrote authorized keys to: %s", path)
	}
	logrus.Info("Wrote authorized keys to server filesystem.")

	go s.Server.Serve()
}

func NewTestClient(t *testing.T, s *TestServer, username string) *TestClient {
	c := new(TestClient)

	// TODO: make a better way to store this information
	c.Username = username
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

	c.FileSystem = &fstest.MapFS{
		"home/username/.hop/" + common.DefaultKeyFile: &fstest.MapFile{
			Data: []byte(c.KeyPair.Private.String() + "\n"),
			Mode: 0600,
		},
	}

	logrus.Info("Created new test client...")
	return c
}

func (c *TestClient) AddAgentConnToClient(t *testing.T, a *TestAgent) {
	logrus.Info("adding agent conn to client")
	aconn, err := net.Dial("tcp", a.Listener.Addr().String())
	assert.NilError(t, err)
	c.AgentConn = aconn
}

// will start a client using an external authenticator if one is set
// otherwise it will use an authgrant conn if provided
// otherwise it will use an agentconn if provided
// lastly it will just call Dial and let hopclient determine method from config
func (c *TestClient) StartClient(t *testing.T) {
	var err error
	c.Client, err = hopclient.NewHopClient(&c.Config, c.Hostname)
	c.Client.Fsystem = *c.FileSystem
	assert.NilError(t, err)
	if c.Authenticator != nil {
		err = c.Client.DialExternalAuthenticator(c.Remote, c.Authenticator)
	} else if c.AgentConn != nil || c.AuthgrantConn != nil {
		err = c.Client.DialExternalConn(c.AgentConn, c.AuthgrantConn)
	} else {
		err = c.Client.Dial()
	}
	assert.NilError(t, err)
}

func NewAgent(t *testing.T) *TestAgent {
	a := new(TestAgent)
	a.Data = &agent.Data{}
	a.Data.Keys = make(map[string]*keys.X25519KeyPair)
	return a
}

func (a *TestAgent) AddClientKey(t *testing.T, c *TestClient) {
	path := "home/" + c.Username + "/.hop/" + common.DefaultKeyFile
	a.Data.Keys[path] = c.KeyPair
}

func (a *TestAgent) Run(t *testing.T) {
	a.Agent = agent.New(a.Data)
	sock, err := net.Listen("tcp", "127.0.0.1:")
	assert.NilError(t, err)
	logrus.Infof("agent listening on %s", sock.Addr().String())
	a.Listener = sock
	go http.Serve(sock, a.Agent)
}

func TestHopClientExtAuth(t *testing.T) {
	logrus.SetLevel(logrus.InfoLevel)
	thunks.SetUpTest()
	t.Run("connect external authenticator", func(t *testing.T) {
		// Create the basic Client and Server
		s := NewTestServer(t)
		c := NewTestClient(t, s, "username")

		// Modify authentication details
		s.AddClientToAuthorizedKeys(t, c)

		s.StartTransport(t)
		s.StartHopServer(t)

		c.Authenticator = s.ChainAuthenticator(t, c.KeyPair)

		c.StartClient(t)
	})
}

func TestHopClientInMemAuth(t *testing.T) {
	logrus.SetLevel(logrus.InfoLevel)
	thunks.SetUpTest()
	t.Run("connect in memory authenticator", func(t *testing.T) {
		// Create the basic Client and Server
		s := NewTestServer(t)
		c := NewTestClient(t, s, "username")

		// Modify authentication details
		s.AddClientToAuthorizedKeys(t, c)

		s.StartTransport(t)
		s.StartHopServer(t)

		c.StartClient(t)
	})
}

func TestHopClientAgentAuth(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	thunks.SetUpTest()
	t.Run("connect agent authenticator", func(t *testing.T) {
		// Create the basic Client and Server
		s := NewTestServer(t)
		c := NewTestClient(t, s, "username")

		// Modify authentication details
		s.AddClientToAuthorizedKeys(t, c)

		s.StartTransport(t)
		s.StartHopServer(t)

		// Start agent for client
		a := NewAgent(t)
		a.AddClientKey(t, c)
		a.Run(t)

		c.AddAgentConnToClient(t, a)

		c.StartClient(t)
	})
}

func TestTwoClients(t *testing.T) {
	logrus.SetLevel(logrus.InfoLevel)
	thunks.SetUpTest()
	t.Run("connect two clients", func(t *testing.T) {
		// Create the basic Client and Server
		s := NewTestServer(t)
		c := NewTestClient(t, s, "username")
		cTwo := NewTestClient(t, s, "bob")

		// Modify authentication details
		s.AddClientToAuthorizedKeys(t, c)
		s.AddClientToAuthorizedKeys(t, cTwo)

		s.StartTransport(t)
		s.StartHopServer(t)

		c.Authenticator = s.ChainAuthenticator(t, c.KeyPair)
		cTwo.Authenticator = s.ChainAuthenticator(t, cTwo.KeyPair)

		wg := sync.WaitGroup{}
		wg.Add(1)

		go func() {
			defer wg.Done()
			c.StartClient(t)
		}()

		cTwo.StartClient(t)
		wg.Wait()
	})
}
