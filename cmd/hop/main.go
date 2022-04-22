package main

import (
	"flag"
	"os"

	"github.com/sirupsen/logrus"

	"zmap.io/portal/config"
	"zmap.io/portal/core"
	"zmap.io/portal/flags"
	"zmap.io/portal/hopclient"
)

func main() {
	var f flags.Flags
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

	// TODO(baumanl): Right now all explicit commands are run within the context
	// of a shell using "$SHELL -c <cmd>" (this allows for expanding env
	// variables, piping, etc.) However, there may be instances where this is
	// undesirable. Add an option to resort to running the command without this
	// feature. Decide which is the better default. Add config/enforcement on
	// what clients/auth grants are allowed to do. How should this be
	// communicated within Intent and in Authgrant?

	// var runCmdInShell bool
	// fs.BoolVar(&runCmdInShell, "s", false, "run specified command...")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		logrus.Fatalf("%s", err)
	}
	if fs.NArg() < 1 { // there needs to be an argument that is not a flag of the form [user@]host[:port]
		logrus.Fatal("missing [hop://][user@]host[:port]")
	}
	hoststring := fs.Arg(0)
	inputURL, err := core.ParseURL(hoststring)
	if err != nil {
		logrus.Fatalf("invalid input %s: %s", hoststring, err)
	}
	// Make client config
	// Load the config
	err = config.InitClient(f.ConfigPath)
	if err != nil {
		logrus.Fatalf("error loading config: %s", err)
	}
	cc := config.GetClient()

	// Make authenticator

	config, address, authenticator := hopclient.ClientSetup(f, inputURL)

	client, err := hopclient.NewHopClient(config)
	if err != nil {
		logrus.Error(err)
		return
	}

	err = client.Dial(address, authenticator)
	if err != nil {
		logrus.Error(err)
		return
	}
	err = client.Start()
	if err != nil {
		logrus.Error(err)
		return
	}
}
