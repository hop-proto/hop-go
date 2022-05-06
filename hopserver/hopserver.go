package hopserver

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"testing/fstest"
	"time"

	"github.com/sbinet/pstree"
	"github.com/sirupsen/logrus"

	"zmap.io/portal/authgrants"
	"zmap.io/portal/certs"
	"zmap.io/portal/config"
	"zmap.io/portal/core"
	"zmap.io/portal/keys"
	"zmap.io/portal/pkg/glob"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
)

// DefaultHopAuthSocket is the default UDS used for Authorization grants
const DefaultHopAuthSocket = "@hopauth"

//HopServer represents state/conns needed for a hop server
type HopServer struct {
	m                     sync.Mutex
	principals            map[int32]*hopSession
	authgrants            map[keys.PublicKey]*authGrant //static key -> authgrant associated with that key
	outstandingAuthgrants int
	config                *config.ServerConfig

	fsystem fs.FS

	server   *transport.Server
	authsock net.Listener
}

//Config contains hop server specific configuration settings
// type Config struct {
// 	SockAddr                 string
// 	MaxOutstandingAuthgrants int
// 	AuthorizedKeysLocation   string //defaults to /.hop/authorized_keys
// }

// NewHopServer returns a Hop Server containing a transport server running on
// the host/port specified in the config file and an authgrant server listening
// on the provided socket.
func NewHopServer(underlying *transport.Server, hconfig *config.ServerConfig) (*HopServer, error) {
	// TODO(baumanl): reintegrate authgrant server
	// set up authgrantServer (UDS socket)
	// make sure the socket does not already exist.
	// if err := os.RemoveAll(hconfig.SockAddr); err != nil {
	// 	logrus.Error(err)
	// 	return nil, err
	// }

	// set socket options and start listening to socket
	// sockconfig := &net.ListenConfig{Control: setListenerOptions}
	// authgrantServer, err := sockconfig.Listen(context.Background(), "unix", hconfig.SockAddr)
	// if err != nil {
	// 	logrus.Error("S: UDS LISTEN ERROR:", err)
	// 	return nil, err
	// }
	// logrus.Infof("address: %v", authgrantServer.Addr())

	principals := make(map[int32]*hopSession)         //PID -> principal hop session
	authgrants := make(map[keys.PublicKey]*authGrant) //static key -> authgrant

	server := &HopServer{
		m:                     sync.Mutex{},
		principals:            principals,
		authgrants:            authgrants,
		outstandingAuthgrants: 0,
		config:                hconfig,

		server: underlying,
		// authsock: authgrantServer,

		fsystem: os.DirFS("/"),
	}
	return server, nil
}

// Close currently just allows the hop server to explicitly shut down the
// authsock. TODO (baumanl): this is hacky & incomplete. Clarify when this
// should happen and all it should do.
func (s *HopServer) Close() {
	s.authsock.Close()
}

//Serve listens for incoming hop connection requests and start corresponding authGrantServer on a Unix Domain socket
func (s *HopServer) Serve() {
	// logrus.SetLevel(logrus.InfoLevel)

	go s.server.Serve() //start transport layer server
	// TODO(baumanl): re-enable after integrating config to server side
	// go s.authGrantServer() //start authgrant server

	//*****ACCEPT CONNS AND START SESSIONS*****
	logrus.Info("hop server starting")
	for {
		serverConn, err := s.server.AcceptTimeout(30 * time.Minute)
		if err != nil {
			logrus.Fatalf("S: SERVER TIMEOUT: %v", err)
		}
		logrus.Infof("S: ACCEPTED NEW CONNECTION")
		go s.newSession(serverConn)
	}
}

// newSession Starts a new hop session
func (s *HopServer) newSession(serverConn *transport.Handle) {
	sess := &hopSession{
		transportConn:   serverConn,
		tubeMuxer:       tubes.NewMuxer(serverConn, serverConn),
		tubeQueue:       make(chan *tubes.Reliable),
		done:            make(chan int),
		controlChannels: []net.Conn{},
		server:          s,
		// authorizedKeysLocation: s.config.AuthorizedKeysLocation,
	}
	// if sess.authorizedKeysLocation != sess.server.config.AuthorizedKeysLocation {
	// 	logrus.Error("Authorized Keys location mismatch")
	// } else {
	// 	logrus.Info("ALL GOOD AUTH KEYS LOCATION")
	// }
	sess.start()
}

//handles connections to the hop server UDS to allow hop client processes to get authorization grants from their principal
func (s *HopServer) authGrantServer() {
	defer s.authsock.Close()
	logrus.Info("S: STARTED LISTENING AT UDS: ", s.authsock.Addr().String())

	for {
		c, err := s.authsock.Accept()
		if err != nil {
			logrus.Error("accept error:", err)
			continue
		}
		go func() {
			//Verify that the client is a legit descendent
			ancestor, e := s.checkCredentials(c)
			if e != nil {
				logrus.Errorf("S: ISSUE CHECKING CREDENTIALS: %v", e)
				return
			}
			s.m.Lock()
			// find corresponding session
			principalSess := s.principals[ancestor]
			s.m.Unlock()
			s.proxyAuthGrantRequest(principalSess, c)
		}()
	}
}

// SetFSystem is a setter currently just used for testing (alt to exporting fsystem)
func (s *HopServer) SetFSystem(fsystem fstest.MapFS) {
	s.fsystem = fsystem
}

//proxyAuthGrantRequest is used by Server to forward INTENT_REQUESTS from a Client -> Principal and responses from Principal -> Client
//Checks hop client process is a descendent of the hop server and conducts authgrant request with the appropriate principal
func (s *HopServer) proxyAuthGrantRequest(principalSess *hopSession, c net.Conn) {
	logrus.Info("S: ACCEPTED NEW UDS CONNECTION")
	defer c.Close()

	if principalSess.transportConn.IsClosed() {
		logrus.Error("S: Connection with Principal is closed")
		return
	}
	logrus.Infof("S: CLIENT CONNECTED [%s]", c.RemoteAddr().Network())
	agc := authgrants.NewAuthGrantConn(c)
	principalAgc, err := authgrants.NewAuthGrantConnFromMux(principalSess.tubeMuxer)
	if err != nil {
		logrus.Errorf("S: ERROR MAKING AGT WITH PRINCIPAL: %v", err)
		return
	}
	defer principalAgc.Close()
	logrus.Infof("S: CREATED AGC")
	for {
		req, e := agc.ReadIntentRequest()
		if e != nil { //if client closes agc this will error out and the loop will end
			logrus.Info("Delegate client closed IPC AGC with delegate server.")
			return
		}
		err = principalAgc.WriteRawBytes(req)
		if err != nil {
			logrus.Errorf("S: ERROR WRITING TO CHANNEL: %v", err)
			return
		}
		logrus.Infof("S: WROTE INTENT_REQUEST TO AGC")
		_, response, err := principalAgc.ReadResponse()
		if err != nil {
			logrus.Errorf("S: ERROR GETTING RESPONSE: %v, %v", err, response)
			return
		}
		err = agc.WriteRawBytes(response)
		if err != nil {
			logrus.Errorf("S: ERROR WRITING TO CHANNEL: %v", err)
			return
		}
	}
}

//verifies that client is a descendent of a process started by the principal and returns its ancestor process PID if found
func (s *HopServer) checkCredentials(c net.Conn) (int32, error) {
	pid, err := readCreds(c)
	if err != nil {
		return 0, err
	}
	//PID of client process that connected to socket
	cPID := pid
	//ancestor represents the PID of the ancestor of the client and child of server daemon
	var ancestor int32 = -1
	//get a picture of the entire system process tree
	tree, err := pstree.New()
	if err != nil {
		return 0, err
	}
	//check all of the PIDs of processes that the server started
	s.m.Lock()
	for k := range s.principals {
		if k == cPID || checkDescendents(tree, tree.Procs[int(k)], int(cPID)) {
			ancestor = k
			break
		}
	}
	s.m.Unlock()
	if ancestor == -1 {
		return 0, errors.New("not a descendent process")
	}
	logrus.Info("S: CREDENTIALS VERIFIED")
	return ancestor, nil
}

// checks tree (starting at proc) to see if cPID is a descendent
func checkDescendents(tree *pstree.Tree, proc pstree.Process, cPID int) bool {
	for _, child := range proc.Children {
		if child == cPID || checkDescendents(tree, tree.Procs[child], cPID) {
			return true
		}
	}
	return false
}

// ListenAddress returns the underlying net.UDPAddr of the transport server.
func (s *HopServer) ListenAddress() net.Addr {
	s.m.Lock()
	defer s.m.Unlock()
	if s.server == nil {
		return &net.UDPAddr{}
	}
	return s.server.ListenAddress()
}

// authorizeKey returns true if the publicKey is in the authorized_keys file for
// the user.
func (s *HopServer) authorizeKey(user string, publicKey keys.PublicKey) error {
	d, err := config.UserDirectoryFor(user)
	if err != nil {
		return err
	}
	path := core.AuthorizedKeysPath(d)
	f, err := s.fsystem.Open(path[1:])
	if err != nil {
		return err
	}
	akeys, err := core.ParseAuthorizedKeys(f)
	if err != nil {
		return nil
	}
	if akeys.Allowed(publicKey) {
		return nil
	}
	return fmt.Errorf("key %s is not authorized for user %s", publicKey, user)
}

// VirtualHosts is mapping from host patterns to Certificates.
type VirtualHosts []VirtualHost

// VirtualHost is a pattern-certificate pairing.
type VirtualHost struct {
	Pattern     string
	Certificate transport.Certificate
}

func transportCert(keyPath, certPath, intermediatePath string) (*transport.Certificate, error) {
	keyPair, err := keys.ReadDHKeyFromPEMFile(keyPath)
	if err != nil {
		return nil, err
	}
	leaf, rawLeaf, err := certs.ReadCertificateBytesFromPEMFile(certPath)
	if err != nil {
		return nil, err
	}
	var rawIntermediate []byte
	if intermediatePath != "" {
		_, rawIntermediate, err = certs.ReadCertificateBytesFromPEMFile(intermediatePath)
		if err != nil {
			return nil, err
		}
	}
	return &transport.Certificate{
		RawLeaf:         rawLeaf,
		RawIntermediate: rawIntermediate,
		Exchanger:       keyPair,
		Leaf:            leaf,
	}, nil

}

// NewVirtualHosts constructs a VirtualHost object from a server
// configmap[string]transport.Certificate{}.
func NewVirtualHosts(c *config.ServerConfig, fallbackKey *keys.X25519KeyPair, fallbackCert *certs.Certificate) (VirtualHosts, error) {
	out := make([]VirtualHost, 0, len(c.Names)+1)
	for _, block := range c.Names {
		// TODO(dadrian)[2022-12-26]: If certs are shared, we'll re-parse all
		// these. We could use some kind of content-addressable store to cache
		// these after a single load pass across the whole config.
		tc, err := transportCert(block.Key, block.Certificate, block.Intermediate)
		if err != nil {
			return nil, err
		}
		out = append(out, VirtualHost{
			Pattern:     block.Pattern,
			Certificate: *tc,
		})
	}
	if c.Key != "" {
		tc, err := transportCert(c.Key, c.Certificate, c.Intermediate)
		if err != nil {
			return nil, err
		}
		out = append(out, VirtualHost{
			Pattern:     "*",
			Certificate: *tc,
		})
	}
	return out, nil
}

// Match returns the first VirtualHost where the pattern glob matches the name.
// It return nil if none are found.
//
// TODO(dadrian)[2022-02-26]: This only does raw string matching, it needs to
// have some way to disambiguate name types.
func (vhosts VirtualHosts) Match(name certs.Name) *VirtualHost {
	for i := range vhosts {
		logrus.Infof("pattern, in: %q, %s", vhosts[i].Pattern, string(name.Label))
		if glob.Glob(vhosts[i].Pattern, string(name.Label)) {
			return &vhosts[i]
		}
	}
	return nil
}
