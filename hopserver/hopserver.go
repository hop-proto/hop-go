package hopserver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing/fstest"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/authkeys"
	"hop.computer/hop/certs"
	"hop.computer/hop/common"
	"hop.computer/hop/config"
	"hop.computer/hop/core"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg/glob"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"
)

// HopServer represents state/conns needed for a hop server
type HopServer struct {
	m sync.Mutex

	// Target server state
	agMap *authgrants.AuthgrantMapSync

	// Delegate proxy server state
	dpProxy *agProxy

	// Session management
	// +checklocks:sessionLock
	sessions      map[sessID]*hopSession
	sessionLock   sync.Mutex
	nextSessionID atomic.Uint32

	config *config.ServerConfig

	fsystem fs.FS

	server   *transport.Server
	keyStore *authkeys.SyncAuthKeySet
	authsock net.Listener //nolint TODO(hosono) add linting back
}

// TODO(baumanl): Think about how NewHopServerExt and NewHopServer and actual
// initialization interact. See PR #91.

// NewHopServerExt returns a Hop Server using the provided transport server.
func NewHopServerExt(underlying *transport.Server, config *config.ServerConfig, ks *authkeys.SyncAuthKeySet) (*HopServer, error) {
	agproxyUnixSocket := common.DefaultAgProxyListenSocket
	if config.AgProxyListenSocket != nil {
		agproxyUnixSocket = *config.AgProxyListenSocket
	}
	server := &HopServer{
		m: sync.Mutex{},

		agMap: authgrants.NewAuthgrantMapSync(),

		dpProxy: &agProxy{
			address:       agproxyUnixSocket,
			principals:    make(map[int32]sessID),
			principalLock: sync.Mutex{},
			runningCV:     sync.Cond{L: &sync.Mutex{}},
			proxyWG:       sync.WaitGroup{},
		},

		sessions:      make(map[sessID]*hopSession),
		sessionLock:   sync.Mutex{},
		nextSessionID: atomic.Uint32{},

		config: config,

		server: underlying,

		fsystem: os.DirFS("/"),
	}

	if (config.EnableAuthorizedKeys != nil && *config.EnableAuthorizedKeys) ||
		(config.EnableAuthgrants != nil && *config.EnableAuthgrants) {
		server.keyStore = ks
	} else {
		server.keyStore = authkeys.NewSyncAuthKeySet()
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
		if h := vhosts.Match(string(info.ServerName.Label)); h != nil {
			return &h.Certificate, nil
		}
		return nil, fmt.Errorf("%v did not match a host block", info.ServerName)
	}

	// This function returns a list of certificates for the hidden mode to determine the vhost associated with the static key.
	getAllowedCerts := func() ([]*transport.Certificate, error) {
		var certificates []*transport.Certificate

		// vhosts.Match is based on patterns and can be "*".
		// If the configuration has more HiddenModeVHostNames than vhosts: return
		if len(sc.HiddenModeVHostNames) > len(vhosts) {
			return nil, fmt.Errorf("number of server Hidden Mode VHost Names exceed the number of current vhosts")
		}

		for _, vhostName := range sc.HiddenModeVHostNames {
			if h := vhosts.Match(vhostName); h != nil {
				h.Certificate.HostNames = append(h.Certificate.HostNames, vhostName)
				certificates = append(certificates, &h.Certificate)
			}

		}
		if len(certificates) == 0 {
			return nil, fmt.Errorf("no certificate found on the server")
		}

		return certificates, nil
	}

	tconf := transport.ServerConfig{
		GetCertificate:       getCert,
		HandshakeTimeout:     sc.HandshakeTimeout,
		ClientVerify:         &transport.VerifyConfig{},
		GetCertList:          getAllowedCerts,
		HiddenModeVHostNames: sc.HiddenModeVHostNames,
	}

	// serverConfig options inform verify config settings
	// 4 main options at the transport layer right now:
	// 1. InsecureSkipVerify: no verification of client cert
	// 2. Certificate Validation ONLY: fails immediately if invalid cert chain
	// 3. Cert Validation or Authorized Keys: will check for auth key and then look at cert chain if that fails
	// 4. Authorized keys only: cert validation explicitly disabled and auth keys explicitly enabled

	// Explicitly setting sc.InsecureSkipVerify overrides everything else
	if sc.InsecureSkipVerify != nil && *sc.InsecureSkipVerify {
		tconf.ClientVerify.InsecureSkipVerify = true
	} else {
		// Cert validation enabled by default (must be explicitly disabled)
		if sc.DisableCertificateValidation == nil || !*sc.DisableCertificateValidation {
			tconf.ClientVerify.Store = certs.Store{}
			for _, s := range sc.CAFiles {
				cert, err := certs.ReadCertificatePEMFile(s)
				if err != nil {
					logrus.Fatalf("server: error loading cert at %s: %s", s, err)
					continue
				}
				logrus.Debugf("server: loaded cert with fingerprint: %x", cert.Fingerprint)
				tconf.ClientVerify.Store.AddCertificate(cert)
			}
		}
		// Authgrants disabled by default (must be explicitly enabled)
		if sc.EnableAuthgrants != nil && *sc.EnableAuthgrants {
			// Create an empty key set for authgrant keys to be added to
			logrus.Debug("created authkeys sync set")
			tconf.ClientVerify.AuthKeys = authkeys.NewSyncAuthKeySet()
			tconf.ClientVerify.AuthKeysAllowed = true
		}

		// Authorized keys disabled by default (must be explicitly enabled)
		if sc.EnableAuthorizedKeys != nil && *sc.EnableAuthorizedKeys {
			logrus.Debug("hopserver: authorized keys are enabled")
			if tconf.ClientVerify.AuthKeys == nil {
				// Create key set if one doesn't already exist from Authgrants being enabled
				logrus.Debug("created authkeys sync set")
				tconf.ClientVerify.AuthKeys = authkeys.NewSyncAuthKeySet()
			}
			// Add all authorized keys from files in specified users' home directories
			for _, name := range sc.Users {
				user, err := user.Lookup(name)
				if err != nil {
					logrus.Errorf("server: error looking up user %s: %s", name, err)
					continue
				}
				authKeysPath := filepath.Join(user.HomeDir, common.UserConfigDirectory, common.AuthorizedKeysFile)
				authKeys, err := core.ParseAuthorizedKeysFile(authKeysPath)
				if err != nil {
					logrus.Errorf("server: error parsing authorized keys file %s: %s", authKeysPath, err)
					continue
				}
				for _, key := range authKeys {
					logrus.Debugf("server: added key %s to authkeys set", key.String())
					tconf.ClientVerify.AuthKeys.AddKey(key)
				}
			}
			tconf.ClientVerify.AuthKeysAllowed = true
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

	// start dpproxy
	s.dpProxy.getPrincipal = func(si sessID) (*hopSession, bool) {
		s.sessionLock.Lock()
		defer s.sessionLock.Unlock()
		sess, ok := s.sessions[si]
		return sess, ok
	}
	err := s.dpProxy.start()
	if err != nil {
		logrus.Error("issue starting dpproxy server")
	}

	for {
		serverConn, err := s.server.AcceptTimeout(30 * time.Minute)
		// io.EOF indicates the server was closed, which is ok
		if errors.Is(err, io.EOF) {
			return
		} else if err != nil {
			logrus.Fatalf("S: SERVER TIMEOUT: %v", err)
		}
		logrus.Infof("S: ACCEPTED NEW CONNECTION")
		go s.newSession(serverConn)
	}
}

// newSession Starts a new hop session
func (s *HopServer) newSession(serverConn *transport.Handle) {
	muxerConfig := tubes.Config{
		Timeout: s.config.DataTimeout,
		Log:     logrus.WithField("muxer", "server"),
	}
	sess := &hopSession{
		transportConn: serverConn,
		// TODO(hosono) add logging context to server
		tubeMuxer:       tubes.Server(serverConn, &muxerConfig),
		controlChannels: []net.Conn{},
		server:          s,
		pty:             make(chan *os.File, 1),
		ID:              sessID(s.nextSessionID.Load()),
	}
	s.nextSessionID.Add(1)
	s.sessionLock.Lock()
	s.sessions[sess.ID] = sess
	s.sessionLock.Unlock()
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

// Close stops the underlying connection and cleans up all resources
// TODO(hosono) this is a very rough sketch of what this method needs to do
func (s *HopServer) Close() error {
	// TODO(hosono) sessions need to acquire s.sessionLock to remove themselves
	// I think all this closing behavior needs to be redone
	s.sessionLock.Lock()
	defer s.sessionLock.Unlock()
	wg := sync.WaitGroup{}
	for sessID := range s.sessions {
		wg.Add(1)
		go func(sess *hopSession) {
			sess.tubeMuxer.Stop()
			wg.Done()
		}(s.sessions[sessID])
	}
	wg.Wait()
	s.dpProxy.stop()
	return s.server.Close()
}

func (s *HopServer) AddAuthGrant(intent *authgrants.Intent) error {
	// TODO(hosono) should authgrants be disabled by default?
	// Can we give the server more fine-grained control over what intents it allows?
	if s.config.EnableAuthgrants != nil && !*s.config.EnableAuthgrants {
		logrus.Warn("Tried to add authgrant, but authgrants are not enabled")
		return fmt.Errorf("authgrants not enabled")
	}
	if intent == nil {
		logrus.Error("intent is nil")
		return fmt.Errorf("intent is nil")
	}

	if s.agMap == nil {
		return fmt.Errorf("agmap is nil")
	}

	if s.keyStore == nil {
		return fmt.Errorf("keystore is nil")
	}

	// add authorization grant to server mappings
	s.agMap.AddAuthGrant(intent, authgrants.PrincipalID(NoSession))

	// add delegate key from cert to transport server authorized key pool
	s.keyStore.AddKey(intent.DelegateCert.PublicKey)

	return nil
}

// authorizeKey returns nil if the publicKey is in the authorized_keys file for
// the user.
func (s *HopServer) authorizeKey(user string, publicKey keys.DHPublicKey) error {
	d, err := config.UserDirectoryFor(user)
	if err != nil {
		return err
	}
	path := core.AuthorizedKeysPath(d)
	f, err := s.fsystem.Open(path[1:])
	if err != nil {
		logrus.Errorf("error opening authkeys file at path: %s", path)
		return err
	}
	akeys, err := core.ParseAuthorizedKeys(f)
	if err != nil {
		return nil
	}
	logrus.Info("successfully parsed authorized keys file")
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

func transportCert(keyPath, certPath, intermediatePath, kemKeyPath string) (*transport.Certificate, error) {
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

	c := &transport.Certificate{
		RawLeaf:         rawLeaf,
		RawIntermediate: rawIntermediate,
		Exchanger:       keyPair,
		Leaf:            leaf,
	}

	if kemKeyPath != "" {
		kemKeyPair, err := keys.ReadKEMKeyFromPEMFile(kemKeyPath)
		if err != nil {
			return nil, err
		}
		c.KEMKeyPair = kemKeyPair
		logrus.Debug("Read kem key from PEM file Hidden Mode activated")
	}

	return c, nil

}

// NewVirtualHosts constructs a VirtualHost object from a server
// configmap[string]transport.Certificate{}.
func NewVirtualHosts(c *config.ServerConfig, fallbackKey *keys.X25519KeyPair, fallbackCert *certs.Certificate) (VirtualHosts, error) {
	out := make([]VirtualHost, 0, len(c.Names)+1)
	for _, block := range c.Names {
		// TODO(dadrian)[2022-12-26]: If certs are shared, we'll re-parse all
		// these. We could use some kind of content-addressable store to cache
		// these after a single load pass across the whole config.
		tc, err := transportCert(block.Key, block.Certificate, block.Intermediate, block.KEMKey)
		if err != nil {
			return nil, err
		}
		out = append(out, VirtualHost{
			Pattern:     block.Pattern,
			Certificate: *tc,
		})
	}
	if c.Key != "" {
		tc, err := transportCert(c.Key, c.Certificate, c.Intermediate, c.KEMKey)
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
func (vhosts VirtualHosts) Match(name string) *VirtualHost {
	for i := range vhosts {
		logrus.Infof("pattern, in: %q, %s", vhosts[i].Pattern, name)
		if glob.Glob(vhosts[i].Pattern, name) {
			return &vhosts[i]
		}
	}
	return nil
}

func (vhosts VirtualHosts) Equal(cert *transport.Certificate) *VirtualHost {
	for i := range vhosts {
		if bytes.Equal(vhosts[i].Certificate.RawLeaf, cert.RawLeaf) &&
			bytes.Equal(vhosts[i].Certificate.RawIntermediate, cert.RawIntermediate) {
			return &vhosts[i]
		}
	}
	return nil
}
