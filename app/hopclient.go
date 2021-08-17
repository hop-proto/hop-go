package app

import (
	"flag"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/codex"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
	"zmap.io/portal/userauth"
)

var hostToIPAddr = map[string]string{
	"scratch-01": "10.216.2.64",
	"scratch-02": "10.216.2.128",
	"scratch-07": "10.216.2.208",
	"localhost":  "127.0.0.1",
}

//Client parses cmd line arguments and establishes hop session with remote hop server
func Client(args []string) {
	//logrus.SetOutput(io.Discard)
	logrus.SetLevel(logrus.InfoLevel)
	//******PROCESS CMD LINE ARGUMENTS******
	if len(args) < 4 {
		logrus.Fatal("C: Invalid arguments. Usage: hop user@host:port -k <pathtokey> or hop user@host:port -a <action>.")
	}
	s := strings.SplitAfter(args[1], "@") //TODO(bauman): Add support for optional username
	user := s[0][0 : len(s[0])-1]
	addrParts := strings.SplitAfter(s[1], ":")
	hostname := addrParts[0][0 : len(addrParts[0])-1]
	port := addrParts[1]
	addr := hostname + ":" + port
	if ip, ok := hostToIPAddr[hostname]; ok {
		addr = ip + ":" + port
	}
	logrus.Infof("Using path: %v", addr)

	var fs flag.FlagSet
	var keypath string
	var principal bool
	fs.Func("k", "indicates principal and key location", func(s string) error {
		principal = true
		keypath = s
		return nil
	})

	//TODO: implement this option to allow for piping and expansion
	//var runCmdInShell bool
	// fs.BoolVar(&runCmdInShell, "s", false, "run specified command within a shell")

	var cmd string
	fs.StringVar(&cmd, "c", "", "specific command to execute on remote server")

	fs.Parse(os.Args[2:])

	config := transport.ClientConfig{}

	//Check if this is a principal client process or one that needs to get an AG
	//******GET AUTHORIZATION SOURCE******

	if principal {
		logrus.Infof("C: Using key-file at %v for auth.", keypath)
		var e error
		if keypath == "path" { //TODO(baumanl): fix default behavior for general program (i.e. Delete this)
			logrus.Info("C: using default key at ~/.hop/key")
			keypath, _ = os.UserHomeDir()
			keypath += "/.hop/key"
		}
		config.KeyPair, e = keys.ReadDHKeyFromPEMFile(keypath)
		if e != nil {
			logrus.Fatalf("C: Error using key at path %v. Error: %v", keypath, e)
		}
	} else {
		if cmd == "" {
			logrus.Error("Authgrant requires an explicit action")
			return
		}
		config.KeyPair = new(keys.X25519KeyPair)
		config.KeyPair.Generate()
		logrus.Infof("Client generated: %v", config.KeyPair.Public.String())
		logrus.Infof("C: Initiating AGC Protocol.")
		t, e := authgrants.GetAuthGrant(config.KeyPair.Public, user, addr, cmd)
		if e != nil {
			logrus.Fatalf("C: %v", e)
		}
		logrus.Infof("C: Principal approved request. Deadline: %v", t)
	}

	//******ESTABLISH HOP SESSION******
	//TODO(baumanl): figure out addr format requirements + check for them above
	transportConn, err := transport.Dial("udp", addr, &config) //There seem to be limits on Dial() and addr format
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
	if ok := userauth.RequestAuthorization(uaCh, config.KeyPair.Public, user); !ok {
		logrus.Fatal("Not authorized.")
	}
	logrus.Info("User authorization complete")

	//*****RUN COMMAND (BASH OR AG ACTION)*****
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
			} else if c.Type() == tubes.NetProxyTube {
				//go do something?
			} else if c.Type() == tubes.ExecTube {
				//go do something else?
			} else {
				//bad tube
				c.Close()
				continue
			}
		}
	}()
	wg.Wait() //client program ends when the code execution tube ends.
	//TODO(baumanl): figure out definitive closing behavior --> multiple code exec tubes?
	logrus.Info("Done waiting")
}
