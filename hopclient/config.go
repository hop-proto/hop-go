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

	var authenticator core.Authenticator
	keyPath := combinators.StringOr(hc.Key, combinators.StringOr(cc.Key, config.DefaultKeyPath()))

	var leaf *certs.Certificate

	if ac.Available(context.Background()) {
		bc, err := ac.ExchangerFor(context.Background(), keyPath)
		if err != nil {
			logrus.Fatalf("unable to create exchanger for agent with keyID: %s", err)
		}
		var public keys.PublicKey
		copy(bc.Public[:], public[:]) // TODO(baumanl): resolve public key type awkwardness
		leaf = loadLeaf(leafFile, autoSelfSign, &public, address)
		authenticator = core.AgentAuthenticator{
			BoundClient: bc,
			VerifyConfig: transport.VerifyConfig{
				InsecureSkipVerify: true, // TODO
			},
			Leaf: leaf,
		}
	} else {
		// read in key from file
		// TODO(baumanl): move loading key to within Authenticator interface?
		logrus.Infof("using key %q", keyPath)
		keypair, err := keys.ReadDHKeyFromPEMFile(keyPath)
		if err != nil {
			logrus.Fatalf("unable to load key pair %q: %s", keyPath, err)
		}
		leaf = loadLeaf(leafFile, autoSelfSign, &keypair.Public, address)
		logrus.Infof("no agent running")
		authenticator = core.InMemoryAuthenticator{
			X25519KeyPair: keypair,
			VerifyConfig: transport.VerifyConfig{
				InsecureSkipVerify: true, // TODO(dadrian): Host-key verification
			},
			Leaf: leaf,
		}
	}

	// TODO(baumanl): resolve weirdness around creating leaf/loading keys
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
