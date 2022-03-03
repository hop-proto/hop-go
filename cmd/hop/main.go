package main

import (
	"flag"
	"os"
	"os/user"

	"github.com/sirupsen/logrus"

	"zmap.io/portal/app"
	"zmap.io/portal/certs"
	"zmap.io/portal/config"
	"zmap.io/portal/core"
	"zmap.io/portal/keys"
	"zmap.io/portal/pkg/combinators"
	"zmap.io/portal/transport"
)

// Flags holds CLI arguments for the Hop client.
//
// TODO(dadrian): This structure probably needs to get moved to another package.
type Flags struct {
	// TODO(dadrian): What are these args?
	ConfigPath string
	Cmd        string
	RemoteArgs []string
	LocalArgs  []string
	Headless   bool
}

func main() {
	var f Flags
	var fs flag.FlagSet

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

	/*TODO(baumanl): Right now all explicit commands are run within the context of a shell using "$SHELL -c <cmd>"
	(this allows for expanding env variables, piping, etc.) However, there may be instances where this is undesirable.
	Add an option to resort to running the command without this feature.
	Decide which is the better default.
	Add config/enforcement on what clients/auth grants are allowed to do.
	How should this be communicated within Intent and in Authgrant?*/
	//var runCmdInShell bool
	// fs.BoolVar(&runCmdInShell, "s", false, "run specified command...")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		logrus.Fatalf("%s", err)
	}
	if fs.NArg() < 1 { //there needs to be an argument that is not a flag of the form [user@]host[:port]
		logrus.Fatal("missing [hop://][user@]host[:port]")
	}
	hoststring := fs.Arg(0)
	inputURL, err := core.ParseURL(hoststring)
	if err != nil {
		logrus.Fatalf("invalid input %s: %s", hoststring, err)
	}

	// Load the config
	err = config.InitClient(f.ConfigPath)
	if err != nil {
		logrus.Fatalf("error loading config: %s", err)
	}

	hc := config.GetClient().MatchHost(inputURL.Host)
	address := core.MergeURLs(hc.HostURL(), *inputURL)

	if address.User == "" {
		u, err := user.Current()
		if err != nil {
			logrus.Fatalf("user not specified and unable to determine current user: %s", err)
		}
		address.User = u.Username
	}

	// Set up keys
	// TODO(dadrian): This logic should probably live somewhere else
	keyPath := combinators.StringOr(hc.Key, config.DefaultKeyPath())
	logrus.Info(keyPath)
	keypair, err := keys.ReadDHKeyFromPEMFile(keyPath)
	if err != nil {
		logrus.Fatalf("unable to load key pair %q: %s", keyPath, err)
	}

	var leaf *certs.Certificate
	if hc.Certificate != "" {
		leaf, err = certs.ReadCertificatePEMFile(hc.Certificate)
		if err != nil {
			logrus.Fatalf("unable to open certificate: %s", err)
		}
	} else {
		leaf, err = certs.SelfSignLeaf(&certs.Identity{
			PublicKey: keypair.Public,
			Names: []certs.Name{
				certs.RawStringName(address.User),
			},
		})
	}

	authenticator := core.InMemoryAuthenticator{
		KeyPair: keypair,
		VerifyConfig: transport.VerifyConfig{
			InsecureSkipVerify: true, // TODO(dadrian): Host-key verification
		},
	}

	logrus.Info(address)
	if err != nil {
		logrus.Fatalf("unable to handle CLI args: %s", err)
	}
	cConfig := app.HopClientConfig{
		User:        address.User,
		Leaf:        leaf,
		SockAddr:    app.DefaultHopAuthSocket,
		NonPricipal: false,
		Keypath:     "path", // XXX
	}

	client, err := app.NewHopClient(cConfig)
	if err != nil {
		logrus.Error(err)
		return
	}

	err = client.Dial(address.Address(), authenticator)
	if err != nil {
		logrus.Error(err)
		return
	}
	err = client.Start()
	if err != nil {
		logrus.Error(err)
		return
	}
	// handle incoming tubes
	go client.HandleTubes()
	client.Wait() //client program ends when the code execution tube ends or when the port forwarding conns end/fail if it is a headless session
}
