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

	// Connect to the agent
	ac := agent.Client{
		BaseURL:    combinators.StringOr(cc.AgentURL, common.DefaultAgentURL),
		HTTPClient: http.DefaultClient,
	}
	if ac.Available(context.Background()) {
		logrus.Infof("connected to agent at %s", ac.BaseURL)
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

	// Set up keys and certificates
	keyPath := combinators.StringOr(hc.Key, combinators.StringOr(cc.Key, config.DefaultKeyPath()))
	logrus.Infof("using key %q", keyPath)
	keypair, err := keys.ReadDHKeyFromPEMFile(keyPath)
	if err != nil {
		logrus.Fatalf("unable to load key pair %q: %s", keyPath, err)
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
			PublicKey: keypair.Public,
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
		X25519KeyPair: keypair,
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
