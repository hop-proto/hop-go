// Package flags provides support for hop CLI args
package flags

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os/user"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/agent"
	"zmap.io/portal/certs"
	"zmap.io/portal/common"
	"zmap.io/portal/config"
	"zmap.io/portal/core"
	"zmap.io/portal/hopclient"
	"zmap.io/portal/keys"
	"zmap.io/portal/pkg/combinators"
	"zmap.io/portal/transport"
)

// ErrMissingInputURL is returned when hoststring is missing
var ErrMissingInputURL = errors.New("missing [hop://][user@]host[:port]")

// Flags holds CLI arguments for the Hop client.
//
// TODO(dadrian): This structure probably needs to get moved to another package.
type Flags struct {
	ConfigPath string

	Cmd     string
	Address *core.URL

	// TODO(dadrian): What are these args?
	RemoteArgs []string // CLI arguments related to remote port forwarding
	LocalArgs  []string // CLI arguments related to local port forwarding
	Headless   bool     // if no cmd/shell desired (just port forwarding)
}

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

// TODO(baumanl): Put this in a different package
// AuthenticatorSetup either connects to an agent or makes an inmemory authenticator object
func AuthenticatorSetup(cc *config.ClientConfig, f *Flags) (core.Authenticator, error) {
	// Connect to the agent
	ac := agent.Client{
		BaseURL:    combinators.StringOr(cc.AgentURL, common.DefaultAgentURL),
		HTTPClient: http.DefaultClient,
	}

	hc := cc.MatchHost(f.Address.Host)

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
		logrus.Fatalf("no certificate provided and AutoSelfSign is not enabled for %q", f.Address)
	}
	keyPath := combinators.StringOr(hc.Key, combinators.StringOr(cc.Key, config.DefaultKeyPath()))
	var authenticator core.Authenticator

	var leaf *certs.Certificate

	if ac.Available(context.Background()) {
		bc, err := ac.ExchangerFor(context.Background(), keyPath)
		if err != nil {
			logrus.Fatalf("unable to create exchanger for agent with keyID: %s", err)
		}
		var public keys.PublicKey
		copy(bc.Public[:], public[:]) // TODO(baumanl): resolve public key type awkwardness
		leaf = loadLeaf(leafFile, autoSelfSign, &public, *f.Address)
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
		leaf = loadLeaf(leafFile, autoSelfSign, &keypair.Public, *f.Address)
		logrus.Infof("no agent running")
		authenticator = core.InMemoryAuthenticator{
			X25519KeyPair: keypair,
			VerifyConfig: transport.VerifyConfig{
				InsecureSkipVerify: true, // TODO(dadrian): Host-key verification
			},
			Leaf: leaf,
		}
	}
	return authenticator, nil
}

func LoadConfigFromFlags(f *Flags) (*config.ClientConfig, error) {
	// Make client config
	// Load the config file
	err := config.InitClient(f.ConfigPath)
	if err != nil {
		// TODO(baumanl): currently fails if no config file found at provided path or default path
		// Do we want to support case where file literally doesn't exist? Just use default
		// host config and CLI flags?
		return nil, fmt.Errorf("no config file found: %s", err)
	}
	cc := config.GetClient()

	// TODO(baumanl): don't like doing this here. feels janky. What version of the address
	// do each of the different abstractions need?
	// update Address with the real address
	hc := cc.MatchHost(f.Address.Host)
	address := core.MergeURLs(hc.HostURL(), *f.Address)

	if address.User == "" {
		u, err := user.Current()
		if err != nil {
			logrus.Fatalf("user not specified and unable to determine current user: %s", err)
		}
		address.User = u.Username
	}
	*f.Address = address

	return cc, nil // parse config file
}

// defineFlags calls fs.StringVar
func defineFlags(fs *flag.FlagSet, f *Flags) {
	fs.Func("R", "perform remote port forwarding", func(s string) error {
		f.RemoteArgs = append(f.RemoteArgs, s)
		return nil
	})

	fs.Func("L", "perform local port forwarding", func(s string) error {
		f.LocalArgs = append(f.LocalArgs, s)
		return nil
	})

	fs.StringVar(&f.ConfigPath, "C", "", "path to client config (uses ~/.hop/config when unspecified)")

	fs.StringVar(&f.Cmd, "c", "", "specific command to execute on remote server")
	fs.BoolVar(&f.Headless, "N", false, "don't execute a remote command. Useful for just port forwarding.")

	// TODO(baumanl): Right now all explicit commands are run within the context
	// of a shell using "$SHELL -c <cmd>" (this allows for expanding env
	// variables, piping, etc.) However, there may be instances where this is
	// undesirable. Add an option to resort to running the command without this
	// feature. Decide which is the better default. Add config/enforcement on
	// what clients/auth grants are allowed to do. How should this be
	// communicated within Intent and in Authgrant?

	// var runCmdInShell bool
	// fs.BoolVar(&runCmdInShell, "s", false, "run specified command...")
}

// ParseArgs defines and parses the flags from the command line
func ParseArgs(args []string) (*Flags, error) {
	var f *Flags
	var fs *flag.FlagSet
	defineFlags(fs, f)

	err := fs.Parse(args[1:])
	if err != nil {
		return nil, err
	}
	if fs.NArg() < 1 { // there needs to be an argument that is not a flag of the form [user@]host[:port]
		return nil, ErrMissingInputURL
	}
	hoststring := fs.Arg(0)
	inputURL, err := core.ParseURL(hoststring)
	if err != nil {
		return nil, fmt.Errorf("invalid input %s: %s", hoststring, err)
	}
	f.Address = inputURL
	return f, nil
}

// ClientSetup creates a hopclient config with the appropriate ovveride rules with information from Flags and config file
func ClientSetup(f *Flags) (*hopclient.Config, string) {
	// potentially other stuff??? Or not necessary at all???
	return &hopclient.Config{User: f.Address.User}, f.Address.Address()
}
