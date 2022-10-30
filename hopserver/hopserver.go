package hopserver

import (
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"testing/fstest"
	"time"

	"github.com/sbinet/pstree"
	"github.com/sirupsen/logrus"

	"hop.computer/hop/certs"
	"hop.computer/hop/config"
	"hop.computer/hop/core"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg/glob"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"
)

// Authgrants Hop server TODOs
// - Listen for descendent clients and proxy their requests back to principal
// - check that connecting clients have appropriate authgrants for actions.

// HopServer represents state/conns needed for a hop server
type HopServer struct {
	m sync.Mutex

	config *config.ServerConfig

	fsystem fs.FS

	server   *transport.Server
	authsock net.Listener //nolint TODO(hosono) add linting back
}

// NewHopServerExt returns a Hop Server using the provided transport server.
func NewHopServerExt(underlying *transport.Server, config *config.ServerConfig) (*HopServer, error) {
	server := &HopServer{
		m: sync.Mutex{},

		config: config,

		server: underlying,

		fsystem: os.DirFS("/"),
	}
	return server, nil
}

// NewHopServer returns a Hop Server containing a transport server running on
// the host/port specified in the config file.
func NewHopServer(sc *config.ServerConfig) (*HopServer, error) {
	// make transport.Server
	vhosts, err := NewVirtualHosts(sc, nil, nil)
	if err != nil {
		logrus.Fatalf("unable to parse virtual hosts: %s", err)
	}

	pktConn, err := net.ListenPacket("udp", sc.ListenAddress)
	if err != nil {
		logrus.Fatalf("unable to open socket for address %s: %s", sc.ListenAddress, err)
	}
	udpConn := pktConn.(*net.UDPConn)
	logrus.Infof("listening at %s", udpConn.LocalAddr())

	getCert := func(info transport.ClientHandshakeInfo) (*transport.Certificate, error) {
		if h := vhosts.Match(info.ServerName); h != nil {
			return &h.Certificate, nil
		}
		return nil, fmt.Errorf("%v did not match a host block", info.ServerName)
	}

	tconf := transport.ServerConfig{
		ClientVerify: &transport.VerifyConfig{
			InsecureSkipVerify: true, // Do authorized keys instead
		},
		GetCertificate:   getCert,
		HandshakeTimeout: sc.HandshakeTimeout,
	}

	underlying, err := transport.NewServer(udpConn, tconf)
	if err != nil {
		logrus.Fatalf("unable to open transport server: %s", err)
	}

	return NewHopServerExt(underlying, sc)

}

// Serve listens for incoming hop connection requests and start corresponding authGrantServer on a Unix Domain socket
func (s *HopServer) Serve() {
	go s.server.Serve() //start transport layer server

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
		transportConn: serverConn,
		// TODO(hosono) choose timeout. Allow timeout to be configured
		// TODO(hosono) add logging context to server
		tubeMuxer:       tubes.NewMuxer(serverConn, serverConn, s.config.DataTimeout, logrus.WithField("TODO", "add logger to server")),
		tubeQueue:       make(chan tubes.Tube),
		done:            make(chan int),
		controlChannels: []net.Conn{},
		server:          s,
		pty:             make(chan *os.File, 1),
	}
	sess.start()
}

// SetFSystem is a setter currently just used for testing (alt to exporting fsystem)
func (s *HopServer) SetFSystem(fsystem fstest.MapFS) {
	s.fsystem = fsystem
}

// checks tree (starting at proc) to see if cPID is a descendent
func checkDescendents(tree *pstree.Tree, proc pstree.Process, cPID int) bool { // nolint TODO(hosono) add linting back
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
	return s.server.Addr()
}

// authorizeKey returns nil if the publicKey is in the authorized_keys file for
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
