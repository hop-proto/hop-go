package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/user"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/app"
	"zmap.io/portal/config"
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

func configFromCmdLineFlags(args []string) (*app.HopClientConfig, error) {
	cConfig := &app.HopClientConfig{
		TransportConfig: nil, // XXX
		SockAddr:        app.DefaultHopAuthSocket,
		Principal:       false,
		Keypath:         "path", // XXX
	}

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

	err := fs.Parse(args)
	if err != nil {
		return nil, err
	}
	if fs.NArg() < 1 { //there needs to be an argument that is not a flag of the form [user@]host[:port]
		return nil, fmt.Errorf("missing [user@]host[:port]")
	}
	hoststring := fs.Arg(0)

	// Load the config
	err = config.InitClient(f.ConfigPath)
	if err != nil {
		logrus.Fatalf("invalid client config: %s", err)
	}

	// TODO(dadrian): This should probably be a libraary function
	inputURL, err := url.Parse("//" + hoststring) //double slashes necessary since there is never a scheme
	if err != nil {
		logrus.Error(err)
		return nil, err
	}

	matchedURL, err := config.GetClient().MatchURL(inputURL)
	if err != nil {
		logrus.Fatalf("bad url %q: %s", inputURL.String(), err)
	}

	cConfig.Hostname = matchedURL.Hostname()
	cConfig.Port = matchedURL.Port()

	username := matchedURL.User.Username()
	if username == "" { //if no username is entered use local client username
		u, err := user.Current()
		if err != nil {
			return nil, err
		}
		cConfig.Username = u.Username
	}
	return cConfig, nil
}

func main() {
	cConfig, err := configFromCmdLineFlags(os.Args[1:])
	if err != nil {
		logrus.Error(err)
		return
	}
	client, err := app.NewHopClient(cConfig)
	if err != nil {
		logrus.Error(err)
		return
	}
	err = client.Connect()
	if err != nil {
		logrus.Error(err)
		return
	}
	err = client.Start()
	if err != nil {
		logrus.Error(err)
		return
	}
	//handle incoming tubes
	go client.HandleTubes()
	client.Wait() //client program ends when the code execution tube ends or when the port forwarding conns end/fail if it is a headless session
}
