package hopclient

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sync"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/agent"
	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/codex"
	"hop.computer/hop/common"
	"hop.computer/hop/config"
	"hop.computer/hop/core"
	"hop.computer/hop/keys"
	"hop.computer/hop/pkg/combinators"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"
	"hop.computer/hop/userauth"
)

// HopClient holds state for client's perspective of session. It is not safe to
// copy a HopClient.
type HopClient struct { // nolint:maligned
	m  sync.Mutex     // must be held whenever changing state (connecting)
	wg sync.WaitGroup // incremented while a connection opens, decremented when it ends

	connected     bool // true if connected to address
	authenticator core.Authenticator

	Fsystem fs.FS

	TransportConn *transport.Client

	// TODO(baumanl): move authgrant state to struct? sort of waiting till i finalize stuff
	// +checklocks:checkIntentLock
	checkIntent     authgrants.CheckIntentCallback // should only be set if principal
	checkIntentLock sync.Mutex
	delServerConn   net.Conn // conn to UDS with delegate server

	TubeMuxer *tubes.Muxer
	ExecTube  *codex.ExecTube

	hostconfig        *config.HostConfig
	RawConfigFilePath string
}

// NewHopClient creates a new client object
func NewHopClient(config *config.HostConfig) (*HopClient, error) {
	logrus.Debugf("new hop client IsPrincipal? %v, IsDelegate? %v", config.IsPrincipal, config.IsDelegate)
	client := &HopClient{
		hostconfig:      config,
		wg:              sync.WaitGroup{},
		Fsystem:         nil,
		checkIntentLock: sync.Mutex{},
	}
	logrus.Info("C: created client: ", client.hostconfig.Hostname)
	return client, nil
}

// TODO(baumanl): think through this Dial stuff better.

// Dial connects to an address after setting up it's own authentication
// using information in it's config.
func (c *HopClient) Dial() error {
	err := c.authenticatorSetup() // TODO(baumanl): or should this be done in NewClient?
	if err != nil {
		return err
	}
	c.m.Lock()
	defer c.m.Unlock()
	// TODO(baumanl): modify interface of connectLocked
	logrus.Info("calling connectLocked on :", c.hostconfig.HostURL().Address())
	return c.connectLocked(c.hostconfig.HostURL().Address(), c.authenticator)
}

// DialExternalAuthenticator connects to an address with the provided authentication.
func (c *HopClient) DialExternalAuthenticator(address string, authenticator core.Authenticator) error {
	c.m.Lock()
	defer c.m.Unlock()
	logrus.Info("calling connectLocked on :", c.hostconfig.HostURL().Address())
	return c.connectLocked(address, authenticator)
}

func (c *HopClient) connectLocked(address string, authenticator core.Authenticator) error {
	if c.connected {
		return errors.New("already connected")
	}
	logrus.Infof("connectLocked to: %q", address)
	err := c.startUnderlying(address, authenticator)
	if err != nil {
		return err
	}
	// TODO(baumanl): Is there something wrong with doing this?
	// This would allow for the same authenticator to be used again during the
	// authgrant procedure.
	// c.address = address
	c.authenticator = authenticator
	c.TubeMuxer = tubes.NewMuxer(c.TransportConn, c.hostconfig.DataTimeout, false, logrus.WithField("muxer", "client"))

	err = c.userAuthorization()
	if err != nil {
		return err
	}
	c.connected = true
	return nil
}

func (c *HopClient) authenticatorSetup() error {
	c.m.Lock()
	defer c.m.Unlock()
	return c.authenticatorSetupLocked()
}

// Client creates an authenticator object from AG, agent, or in mem keys.
func (c *HopClient) authenticatorSetupLocked() error {
	defer logrus.Info("C: authenticator setup complete")
	var authenticator core.Authenticator
	var leaf *certs.Certificate

	hc := c.hostconfig

	verifyConfig := constructVerifyConfig(hc)
	c.loadCAFiles(&verifyConfig.Store)

	if hc.IsDelegate {
		return c.getAuthorization(verifyConfig)
	}

	// Host block overrides global block. Set overrides Unset. Certificate
	// overrides AutoSelfSign.
	var leafFile string
	var autoSelfSign bool
	if hc.Certificate != "" {
		leafFile = hc.Certificate
	} else if hc.AutoSelfSign {
		autoSelfSign = true
	} else {
		return fmt.Errorf("no certificate provided and AutoSelfSign is not enabled for %q", hc.HostURL().Address())
	}
	keyPath := combinators.StringOr(hc.Key, config.DefaultKeyPath())
	agentURL := combinators.StringOr(hc.AgentURL, common.DefaultAgentURL)

	ac := agent.Client{
		BaseURL:    agentURL,
		HTTPClient: http.DefaultClient,
	}

	// Connect to the agent
	aconn, _ := net.Dial("tcp", agentURL)

	if !hc.DisableAgent && aconn != nil && ac.Available(context.Background()) {
		bc, err := ac.ExchangerFor(context.Background(), keyPath)
		if err != nil {
			return fmt.Errorf("unable to create exchanger for agent with keyID: %s", err)
		}

		logrus.Infof("Created exchanger for agent with keyID: %s ", keyPath)

		var public keys.PublicKey
		copy(public[:], bc.Public[:]) // TODO(baumanl): resolve public key type awkwardness
		leaf = loadLeaf(leafFile, autoSelfSign, &public, hc.HostURL())
		authenticator = core.AgentAuthenticator{
			BoundClient:  bc,
			VerifyConfig: verifyConfig,
			Leaf:         leaf,
		}
		logrus.Info("leaf: ", leaf)
	} else {
		// read in key from file
		// TODO(baumanl): move loading key to within Authenticator interface?
		logrus.Infof("using key %q", keyPath)
		keypair, err := keys.ReadDHKeyFromPEMFileFS(keyPath, c.Fsystem)
		if err != nil {
			return fmt.Errorf("unable to load key pair %q: %s", keyPath, err)
		}
		leaf = loadLeaf(leafFile, autoSelfSign, &keypair.Public, hc.HostURL())
		logrus.Infof("no agent running")
		authenticator = core.InMemoryAuthenticator{
			X25519KeyPair: keypair,
			VerifyConfig:  verifyConfig,
			Leaf:          leaf,
		}
	}
	c.authenticator = authenticator
	return nil
}

// TODO(baumanl): Put this in a different package/file

// Creates a self-signed leaf or loads in from leafFile.
func loadLeaf(leafFile string, autoSelfSign bool, public *keys.PublicKey, address core.URL) *certs.Certificate {
	var leaf *certs.Certificate
	var err error
	if autoSelfSign {
		logrus.Infof("auto self-signing leaf for user %q", address.User)
		leaf, err = certs.SelfSignLeaf(&certs.Identity{
			PublicKey: *public,
			Names: []certs.Name{
				certs.RawStringName(address.User),
			},
		})
		if err != nil {
			logrus.Fatalf("unable to self-sign certificate: %s", err)
		}
	} else {
		leaf, err = certs.ReadCertificatePEMFile(leafFile)
		if err != nil {
			logrus.Fatalf("unable to open certificate: %s", err)
		}
	}
	return leaf
}

// Start starts any port forwarding/cmds/shells from the client
func (c *HopClient) Start() error {
	//TODO(baumanl): fix how session duration tied to cmd duration or port
	//forwarding duration depending on options
	logrus.Infof("hostconfig.Cmd: %v", c.hostconfig.Cmd)
	err := c.startExecTube()
	if err != nil {
		logrus.Error(err)
		return ErrClientStartingExecTube
	}

	// handle incoming tubes
	go c.HandleTubes()
	c.Wait() // client program ends when the code execution tube ends or when the port forwarding conns end/fail if it is a headless session
	c.Close()
	return nil
}

// Wait blocks until the client has finished (usually used when waiting for a session tied to cmd/shell to finish)
func (c *HopClient) Wait() {
	c.wg.Wait()
}

// Close explicitly closes down hop session (usually used after PF is down and can be terminated)
func (c *HopClient) Close() error {
	defer logrus.Info("client done waiting!")
	if c.ExecTube != nil {
		c.ExecTube.Restore()
	}
	var err error
	if c.TubeMuxer != nil {
		err = c.TubeMuxer.Stop()
	}

	if c.delServerConn != nil {
		c.delServerConn.Close() // informs del server to close proxy b/w principal + target
	}
	// TODO: close all remote and local port forwarding relationships
	logrus.Info("client waiting in close...")
	c.wg.Wait()
	return err
}

func (c *HopClient) startUnderlying(address string, authenticator core.Authenticator) error {
	// TODO(dadrian): Update this once the authenticator interface is set.
	transportConfig := transport.ClientConfig{
		Exchanger: authenticator,
		Verify:    authenticator.GetVerifyConfig(),
		Leaf:      authenticator.GetLeaf(),
	}
	var err error
	var dialer net.Dialer
	dialer.Timeout = c.hostconfig.HandshakeTimeout
	c.TransportConn, err = transport.DialWithDialer(&dialer, "udp", address, transportConfig)

	if err != nil {
		logrus.Errorf("C: error dialing server: %v", err)
		return err
	}

	// TODO(dadrian): This hangs if the server is not available when it starts.
	// Transport needs to be set with a timeout.
	err = c.TransportConn.Handshake()
	if err != nil {
		logrus.Errorf("C: Issue with handshake: %v", err)
		return err
	}
	return nil
}

func (c *HopClient) userAuthorization() error {
	uaCh, err := c.TubeMuxer.CreateReliableTube(common.UserAuthTube)
	if err != nil {
		logrus.Errorf("error creating userAuthTube")
	}
	defer uaCh.Close()
	logrus.Infof("requesting auth for %s", c.hostconfig.User)
	if ok := userauth.RequestAuthorization(uaCh, c.hostconfig.User); !ok {
		return ErrClientUnauthorized
	}
	logrus.Info("User authorization complete")
	return nil
}

func (c *HopClient) startExecTube() error {
	// Hop Session is tied to the life of this code execution tube if such a tube exists
	// TODO(baumanl): provide support for Cmd in ClientConfig
	logrus.Infof("Performing action: %v", c.hostconfig.Cmd)
	codexTube, err := c.TubeMuxer.CreateReliableTube(common.ExecTube)
	if err != nil {
		logrus.Error(err)
		return err
	}
	winSizeTube, err := c.TubeMuxer.CreateReliableTube(common.WinSizeTube)
	if err != nil {
		codexTube.Close()
		logrus.Error(err)
		return err
	}
	c.ExecTube, err = codex.NewExecTube(c.hostconfig.Cmd, c.hostconfig.UsePty, codexTube, winSizeTube, &c.wg)
	if err == nil {
		c.wg.Add(1)
	} else {
		codexTube.Close()
		winSizeTube.Close()
	}
	return err
}

// HandleTubes handles incoming tube requests to the client
func (c *HopClient) HandleTubes() {
	//TODO(baumanl): figure out responses to different tube types/what all should be allowed

	proxyQueue := newPTProxyTubeQueue()

	for t := range c.TubeMuxer.TubeQueue {
		logrus.Infof("ACCEPTED NEW TUBE OF TYPE: %v. Reliable? %t", t.Type(), t.IsReliable())

		if r, ok := t.(*tubes.Reliable); ok && r.Type() == common.AuthGrantTube && c.hostconfig.IsPrincipal {
			go c.newPrincipalInstanceSetup(r, proxyQueue)
		} else if u, ok := t.(*tubes.Unreliable); ok && u.Type() == common.PrincipalProxyTube && c.hostconfig.IsPrincipal {
			// add to map and signal waiting processes
			proxyQueue.lock.Lock()
			proxyQueue.tubes[u.GetID()] = u
			proxyQueue.lock.Unlock()
			proxyQueue.cv.Broadcast()
			logrus.Infof("session muxer broadcasted that unreliable tube is here: %x", u.GetID())
		} else if t.Type() == common.RemotePFTube {
			panic("client RemotePFTubes: unimplemented")
		} else {
			// Client only expects to receive AuthGrantTubes. All other tube requests are ignored.
			e := t.Close()
			if e != nil {
				logrus.Errorf("Error closing tube: %v", e)
			}
		}
	}
	if !errors.Is(err, io.EOF) {
		logrus.Warnf("error when accepting tube: %v", err)
	}
}
