package hopclient

import (
	"context"
	"net/http"
	"os/user"

	"github.com/sirupsen/logrus"

	"zmap.io/portal/agent"
	"zmap.io/portal/certs"
	"zmap.io/portal/common"
	"zmap.io/portal/config"
	"zmap.io/portal/core"
	"zmap.io/portal/flags"
	"zmap.io/portal/hopserver"
	"zmap.io/portal/keys"
	"zmap.io/portal/pkg/combinators"
	"zmap.io/portal/transport"
)

// ClientSetup uses CLI flags and config file to set up hthe HopClientConfig,
// the address to connect to, and creates authenticator object.
// TODO (baumanl): can be decomposed further + add unit tests.
func ClientSetup(f flags.Flags, inputURL *core.URL) (Config, string, core.Authenticator) {
	// Load the config
	err := config.InitClient(f.ConfigPath)
	if err != nil {
		logrus.Fatalf("error loading config: %s", err)
	}
	cc := config.GetClient()

	// TODO(baumanl): should the agent always be used if available?
	// current assumption: if agent active it has the client's key and we should use it

	// Connect to the agent
	ac := agent.Client{
		BaseURL:    combinators.StringOr(cc.AgentURL, common.DefaultAgentURL),
		HTTPClient: http.DefaultClient,
	}

	hc := cc.MatchHost(inputURL.Host)
	address := core.MergeURLs(hc.HostURL(), *inputURL)

	if address.User == "" {
		u, err := user.Current()
		if err != nil {
			logrus.Fatalf("user not specified and unable to determine current user: %s", err)
		}
		address.User = u.Username
	}

	var keypair *keys.X25519KeyPair // only set if agent not in use
	var public keys.PublicKey       // currently set from file or agent for use in self-signed cert

	keyPath := combinators.StringOr(hc.Key, combinators.StringOr(cc.Key, config.DefaultKeyPath()))
	if ac.Available(context.Background()) {
		logrus.Infof("connected to agent at %s", ac.BaseURL)
		// no need to read key from PEM file --> assume loaded in agent
		keydescr, err := ac.Get(context.Background(), keyPath) // TODO(baumanl): rearrange so this only happens if self-signed cert needed
		if err != nil {
			logrus.Fatalf("agent doesn't have key pair %q: %s", keyPath, err)
		}
		if len(keydescr.Public) != 32 { // TODO(baumanl): check on keydescr.Type?
			logrus.Fatal("unexpected key length")
		}
		copy(keydescr.Public[0:32], public[:]) // TODO(baumanl): best way to do this?

		// certificate could still need to be read from file if issued by CA
		// if basic (like auth_keys functionality) will need to use agent/public-key to generate "self-signed" certificate
	} else {
		// read in key from file
		logrus.Infof("using key %q", keyPath)
		keypair, err = keys.ReadDHKeyFromPEMFile(keyPath) // TODO(baumanl): use agent instead of reading in key
		if err != nil {
			logrus.Fatalf("unable to load key pair %q: %s", keyPath, err)
		}
		public = keypair.Public
		logrus.Infof("no agent running")
	}

	// Host block overrides global block. Set overrides Unset. Certificate
	// overrides AutoSelfSign.
	var leafFile string
	var autoSelfSign bool
	if hc.Certificate != "" {
		leafFile = hc.Certificate
	} else if hc.AutoSelfSign == config.True {
		autoSelfSign = true
	} else if hc.AutoSelfSign != config.True && cc.Certificate != "" {
		leafFile = cc.Certificate
	} else if hc.AutoSelfSign == config.Unset && cc.AutoSelfSign == config.True {
		autoSelfSign = true
	} else {
		logrus.Fatalf("no certificate provided and AutoSelfSign is not enabled for %q", address)
	}

	var leaf *certs.Certificate
	if autoSelfSign {
		logrus.Infof("auto self-signing leaf for user %q", address.User)
		leaf, err = certs.SelfSignLeaf(&certs.Identity{
			PublicKey: public,
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

	authenticator := core.InMemoryAuthenticator{
		X25519KeyPair: keypair, // TODO(baumanl): doesn't make sense if agent in use
		VerifyConfig: transport.VerifyConfig{
			InsecureSkipVerify: true, // TODO(dadrian): Host-key verification
		},
		Leaf: leaf,
	}

	logrus.Info(address)
	cConfig := Config{
		User:     address.User,
		Leaf:     leaf,
		SockAddr: hopserver.DefaultHopAuthSocket,
		Cmd:      f.Cmd,
		// TODO(bauman): allow for more config options for cmds/local/remote PF
		// right now specific cmd can only be specified in cmd line and PF
		// currently disabled

		// TODO(baumanl): set up docker container with more port bindings for PF?
		NonPricipal: false,
	}
	return cConfig, address.Address(), authenticator
}
