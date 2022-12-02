package hopserver

import (
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"testing/fstest"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/authkeys"
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
// - act as a target: authorize/deny intent requests forwarded from principal

type authgrant struct {
	Data      authgrants.AuthGrantData // relevant data from IR
	Principal *hopSession
}

// HopServer represents state/conns needed for a hop server
type HopServer struct {
	m sync.Mutex

	// Target server state
	// TODO(baumanl): potentially don't need entire Intent
	authgrants map[string]map[keys.PublicKey][]authgrant
	agLock     sync.Mutex

	// Delegate proxy server state
	agproxy    *Agproxy
	principals map[*hopSession]*hopSession // principals[sess] is sess that is connected to principal

	config *config.ServerConfig

	fsystem fs.FS

	server   *transport.Server
	keyStore *authkeys.AuthKeySet
	authsock net.Listener //nolint TODO(hosono) add linting back
}

// NewHopServerExt returns a Hop Server using the provided transport server.
func NewHopServerExt(underlying *transport.Server, config *config.ServerConfig, ks *authkeys.AuthKeySet) (*HopServer, error) {
	server := &HopServer{
		m: sync.Mutex{},

		authgrants: make(map[string]map[keys.PublicKey][]authgrant),
		agLock:     sync.Mutex{},

		agproxy: &Agproxy{
			address:    config.AgProxyListenSocket,
			principals: make(map[int32]*hopSession),
			running:    false,
			proxyLock:  sync.Mutex{},
		},

		principals: make(map[*hopSession]*hopSession),

		config: config,

		server: underlying,

		fsystem: os.DirFS("/"),
	}

	if config.EnableAuthorizedKeys != nil && *config.EnableAuthorizedKeys {
		server.keyStore = ks
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
		GetCertificate:   getCert,
		HandshakeTimeout: sc.HandshakeTimeout,
	}

	// serverConfig options inform verify config settings
	// 4 main options right now:
	// 1. InsecureSkipVerify: no verification of client cert
	// 2. Certificate Validation ONLY: fails immediately if invalid cert chain
	// 3. Cert Validation or Authorized Keys: will check for auth key if invalid cert chain
	// 4. Authorized keys only: cert validation explicitly disabled and auth keys explicitly enabled

	// Explicitly setting sc.InsecureSkipVerify overrides everything else
	if sc.InsecureSkipVerify != nil && *sc.InsecureSkipVerify {
		tconf.ClientVerify = &transport.VerifyConfig{
			InsecureSkipVerify: true,
		}
	} else {
		// Cert validation enabled
		if sc.EnableCertificateValidation == nil || *sc.EnableCertificateValidation {
			tconf.ClientVerify = &transport.VerifyConfig{
				Store: certs.Store{}, // TODO(baumanl): get the store from somewhere
			}
		}
		// Authorized keys enabled
		if sc.EnableAuthorizedKeys != nil && *sc.EnableAuthorizedKeys {
			// must be explicitly set to true
			tconf.ClientVerify = &transport.VerifyConfig{
				AuthKeys: authkeys.NewAuthKeySet(), // TODO(baumanl): load initial (stable trusted keys)
			}
		}
	}

	underlying, err := transport.NewServer(udpConn, tconf)
	if err != nil {
		logrus.Fatalf("unable to open transport server: %s", err)
	}

	return NewHopServerExt(underlying, sc, tconf.ClientVerify.AuthKeys)
}

// Serve listens for incoming hop connection requests and starts
// corresponding agproxy on unix socket
func (s *HopServer) Serve() {
	go s.server.Serve() // start transport layer server
	logrus.Info("hop server starting")

	// start agproxy
	err := s.agproxy.Start()
	if err != nil {
		logrus.Error("issue starting agproxy server")
	}

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

func (s *HopServer) authorizeKeyAuthGrant(user string, publicKey keys.PublicKey) ([]authgrant, error) {
	if s.config.AllowAuthgrants != nil && *s.config.AllowAuthgrants {
		s.agLock.Lock()
		defer s.agLock.Unlock()
		if _, ok := s.authgrants[user]; ok {
			// user has some authgrants
			if val, ok := s.authgrants[user][publicKey]; ok {
				delete(s.authgrants[user], publicKey) // remove from server mapping
				if len(s.authgrants[user]) == 0 {     // all authgrants have been removed for user
					delete(s.authgrants, user)
					s.keyStore.RemoveKey(publicKey)
				}
				return val, nil
			}
		}
	}
	return []authgrant{}, fmt.Errorf("auth grants not enabled")
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

func (s *HopServer) addAuthGrant(intent *authgrants.Intent, principalSess *hopSession) {
	s.agLock.Lock()
	defer s.agLock.Unlock()
	user := intent.TargetUsername
	s.authgrants[user] = make(map[keys.PublicKey][]authgrant)
	ag := authgrant{
		Data:      intent.GetData(),
		Principal: principalSess,
	}
	s.authgrants[user][intent.DelegateCert.PublicKey] = append(s.authgrants[user][intent.DelegateCert.PublicKey], ag)
}

// TODO(baumanl): how should expired authgrants be removed?
// 1. how often or at what trigger
// 2. when should key be removed from transport keyStore?
// currently never...expired ones are just ignored

// func (s *HopServer) agCleanup() {
// 	s.agLock.Lock()
// 	defer s.agLock.Unlock()
// 	for _, ps := range s.authgrants {
// 		for k, ags := range ps {
// 			del := true
// 			for _, ag := range ags {
// 				if !ag.Data.ExpTime.Before(time.Now()) {
// 					del = false
// 					break
// 				}
// 			}
// 			if del {
// 				delete(ps, k)
// 				s.keyStore.RemoveKey(k)
// 			}

// 		}
// 	}
// }
