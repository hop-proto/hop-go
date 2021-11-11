package main

import (
	"flag"
	"io"
	"net/url"
	"os"
	"os/user"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/app"
)

func main() {
	_, verify := app.NewTestServerConfig(app.TestDataPathPrefixDef)
	keypath, _ := os.UserHomeDir()
	keypath += app.DefaultKeyPath

	cConfig := &app.HopClientConfig{
		Verify:        *verify,
		SockAddr:      app.DefaultHopAuthSocket,
		Principal:     false,
		Keypath:       keypath,
		RemoteForward: false,
		LocalForward:  false,
	}

	//******PROCESS CMD LINE ARGUMENTS******
	var fs flag.FlagSet

	fs.Func("k", "indicates principal with specific key location", func(s string) error {
		cConfig.Principal = true
		cConfig.Keypath = s
		return nil
	})

	fs.BoolVar(&cConfig.Principal, "K", cConfig.Principal, "indicates principal with default key location: $HOME/.hop/key")

	fs.Func("R", "perform remote port forwarding", func(s string) error {
		cConfig.RemoteForward = true
		cConfig.RemoteArg = s
		return nil
	})

	fs.Func("L", "perform local port forwarding", func(s string) error {
		cConfig.LocalForward = true
		cConfig.LocalArg = s
		return nil
	})

	fs.StringVar(&cConfig.Cmd, "c", "", "specific command to execute on remote server")
	fs.BoolVar(&cConfig.Quiet, "q", false, "turn off logging")
	if cConfig.Quiet {
		logrus.SetOutput(io.Discard)
	}
	fs.BoolVar(&cConfig.Headless, "N", false, "don't execute a remote command. Useful for just port forwarding.")

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
		return
	}
	if fs.NArg() < 1 { //there needs to be an argument that is not a flag of the form [user@]host[:port]
		return
	}
	hoststring := fs.Arg(0)
	if fs.NArg() > 1 { //still flags after the hoststring that need to be parsed
		err = fs.Parse(fs.Args()[1:])
		if err != nil || fs.NArg() > 0 {
			return
		}
	}

	url, err := url.Parse("//" + hoststring) //double slashes necessary since there is never a scheme
	if err != nil {
		logrus.Error(err)
		return
	}

	cConfig.Hostname = url.Hostname()
	cConfig.Port = url.Port()
	if cConfig.Port == "" {
		cConfig.Port = app.DefaultHopPort
	}

	username := url.User.Username()
	if username == "" && cConfig.Username == "" { //if no username is entered use local client username
		u, e := user.Current()
		if e != nil {
			return
		}
		cConfig.Username = u.Username
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
	client.Primarywg.Wait() //client program ends when the code execution tube ends or when the port forwarding conns end/fail if it is a headless session
}
