package app

import (
	"flag"
	"net"
	"net/url"
	"os"
	"os/user"
	"sync"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/codex"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
	"zmap.io/portal/userauth"
)

var hostToIPAddr = map[string]string{ //TODO(baumanl): this should be dealt with in some user hop config file
	"scratch-01": "10.216.2.64",
	"scratch-02": "10.216.2.128",
	"scratch-07": "10.216.2.208",
	"localhost":  "127.0.0.1",
}

//Client parses cmd line arguments and establishes hop session with remote hop server
func Client(args []string) {
	logrus.SetLevel(logrus.InfoLevel)
	//TODO(baumanl): add .hop_config support
	//******PROCESS CMD LINE ARGUMENTS******
	if len(args) < 2 {
		logrus.Fatal("C: Invalid arguments. Usage: ", clientUsage)
	}

	url, err := url.Parse("//" + args[1]) //double slashes necessary since there is never a scheme
	if err != nil {
		logrus.Fatal("C: Destination should be of form: [user@]host[:port]", err)
	}

	hostname := url.Hostname()
	port := url.Port()
	if port == "" {
		port = defaultHopPort
	}
	addr := hostname + ":" + port
	logrus.Infof("Using path: %v", addr)

	username := url.User.Username()
	if username == "" { //if no username is entered use local client username
		u, e := user.Current()
		if e != nil {
			logrus.Error(e)
		}
		username = u.Username
	}

	var fs flag.FlagSet
	keypath, _ := os.UserHomeDir()
	keypath += defaultKeyPath
	principal := false

	fs.Func("k", "indicates principal with specific key location", func(s string) error {
		principal = true
		keypath = s
		return nil
	})

	fs.BoolVar(&principal, "K", principal, "indicates principal with default key location: $HOME/.hop/key")

	//TODO(baumanl): implement this option to allow for piping and expansion
	//var runCmdInShell bool
	// fs.BoolVar(&runCmdInShell, "s", false, "run specified command within a shell")

	var cmd string
	fs.StringVar(&cmd, "c", "", "specific command to execute on remote server")

	err = fs.Parse(os.Args[2:])
	if err != nil {
		logrus.Fatal(err)
	}
	if fs.NArg() > 0 {
		logrus.Fatal("Unknown arguments provided. Usage: ", clientUsage)
	}
	_, verify := newTestServerConfig()
	config := transport.ClientConfig{Verify: *verify} //TODO(baumanl):  I modified ClientConfig to let static keys into the transport protocol. Is this a correct way to do this?

	//Check if this is a principal client process or one that needs to get an AG
	//******GET AUTHORIZATION SOURCE******
	if principal {
		logrus.Infof("C: Using key-file at %v for auth.", keypath)
		var e error
		config.KeyPair, e = keys.ReadDHKeyFromPEMFile(keypath)
		if e != nil {
			logrus.Fatalf("C: Error using key at path %v. Error: %v", keypath, e)
		}
	} else {
		shell := false
		if cmd == "" {
			shell = true
		}
		config.KeyPair = new(keys.X25519KeyPair)
		config.KeyPair.Generate()
		logrus.Infof("Client generated: %v", config.KeyPair.Public.String())
		logrus.Infof("C: Initiating AGC Protocol.")
		t, e := authgrants.GetAuthGrant(config.KeyPair.Public, username, addr, shell, cmd)
		if e != nil {
			logrus.Fatalf("C: %v", e)
		}
		logrus.Infof("C: Principal approved request. Deadline: %v", t)
	}

	//******ESTABLISH HOP SESSION******
	//TODO(baumanl): figure out addr format requirements + check for them above
	if _, err = net.LookupAddr(addr); err != nil {
		//Couldn't resolve address with local resolver
		if ip, ok := hostToIPAddr[hostname]; ok {
			addr = ip + ":" + port
		}
	}
	transportConn, err := transport.Dial("udp", addr, config) //There seem to be limits on Dial() and addr format
	if err != nil {
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	err = transportConn.Handshake() //This hangs if the server is not available when it starts. Add retry or timeout?
	if err != nil {
		logrus.Fatalf("C: Issue with handshake: %v", err)
	}
	//TODO(baumanl): should these functions + things from tubes layer have errors?
	mc := tubes.NewMuxer(transportConn, transportConn)
	go mc.Start()
	defer func() {
		mc.Stop()
		logrus.Info("muxer stopped")
		//TODO: finish closing behavior
		// e := transportConn.Close()
		// logrus.Error("closing transport: ", e)
	}()

	//*****PERFORM USER AUTHORIZATION******
	uaCh, _ := mc.CreateTube(tubes.UserAuthTube)
	if ok := userauth.RequestAuthorization(uaCh, config.KeyPair.Public, username); !ok {
		logrus.Fatal("Not authorized.")
	}
	logrus.Info("User authorization complete")

	//*****RUN COMMAND (BASH OR AG ACTION)*****
	//Hop Session is tied to the life of this code execution tube.
	logrus.Infof("Performing action: %v", cmd)
	ch, _ := mc.CreateTube(tubes.ExecTube)
	wg := sync.WaitGroup{}
	wg.Add(1)
	execCh := codex.NewExecTube(cmd, ch, &wg)

	//TODO(baumanl): figure out responses to different tube types/what all should be allowed
	//*****START LISTENING FOR INCOMING CHANNEL REQUESTS*****
	go func() {
		for {
			c, e := mc.Accept()
			if e != nil {
				logrus.Fatalf("Error accepting tube: %v", e)
			}
			logrus.Infof("ACCEPTED NEW CHANNEL of TYPE: %v", c.Type())
			if c.Type() == tubes.AuthGrantTube && principal {
				go authgrants.Principal(c, mc, execCh, &config)
			} else {
				//Client only expects to receive AuthGrantTubes. All other tube requests are ignored.
				c.Close()
				continue
			}
		}
	}()
	wg.Wait() //client program ends when the code execution tube ends.
	//TODO(baumanl): figure out definitive closing behavior --> multiple code exec tubes?
	logrus.Info("Done waiting")
}
