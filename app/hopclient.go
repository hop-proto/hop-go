package main

import (
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/channels"
	"zmap.io/portal/codex"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

//parses cmd line arguments and establishes hop session with remote hop server
func client(args []string) {
	logrus.SetLevel(logrus.InfoLevel)
	//******PROCESS CMD LINE ARGUMENTS******
	if len(args) < 5 {
		logrus.Fatal("C: Invalid arguments. Useage: hop user@host:port -k <pathtokey> or hop user@host:port -a <action>.")
	}
	s := strings.SplitAfter(args[2], "@") //TODO(bauman): Add support for optional username
	user := s[0][0 : len(s[0])-1]
	addr := s[1]
	//TODO(bauman): get users default shell ($SHELL ?)
	cmd := []string{"bash"} //default action for principal is to open an interactive shell
	config := transport.ClientConfig{}

	//Check if this is a principal client process or one that needs to get an AG
	//******GET AUTHORIZATION SOURCE******
	var principal bool
	if args[3] == "-k" {
		principal = true
		logrus.Infof("C: Using key-file at %v for auth.", args[4])
		var e error
		path := args[4]
		if path == "path" {
			logrus.Info("C: using default key")
			path = "keys/default" //TODO(baumanl): fix default behavior for general program
		}
		config.KeyPair, e = keys.ReadDHKeyFromPEMFile(path)
		if e != nil {
			logrus.Fatalf("C: Error using key at path %v. Error: %v", path, e)
		}
	} else if args[3] == "-a" {
		principal = false
		config.KeyPair = new(keys.X25519KeyPair)
		config.KeyPair.Generate()
		logrus.Infof("Client generated: %v", config.KeyPair.Public.String())
		logrus.Infof("C: Initiating AGC Protocol.")
		cmd = args[4:]                                                          //if using authorization grant then perform the action specified in cmd line
		t, e := authgrants.GetAuthGrant(config.KeyPair.Public, user, addr, cmd) //TODO(baumanl): necessary to store the deadline somewhere?
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
	//TODO(baumanl): should these functions + things from Channels layer have errors?
	mc := channels.NewMuxer(transportConn, transportConn)
	go mc.Start()
	defer func() {
		mc.Stop()
		logrus.Info("muxer stopped")
	}()

	//*****RUN COMMAND (BASH OR AG ACTION)*****
	logrus.Infof("Performing action: %v", cmd)
	ch, _ := mc.CreateChannel(channels.EXEC_CHANNEL)
	wg := sync.WaitGroup{}
	wg.Add(1)
	exec_ch := codex.NewExecChan(cmd, ch, &wg)

	//TODO(baumanl): figure out responses to different channel types/what all should be allowed
	//*****START LISTENING FOR INCOMING CHANNEL REQUESTS*****
	go func() {
		for {
			c, e := mc.Accept()
			if e != nil {
				logrus.Fatalf("Error accepting channel: ", e)
			}
			logrus.Infof("ACCEPTED NEW CHANNEL of TYPE: %v", c.Type())
			if c.Type() == channels.AGC_CHANNEL && principal {
				go authgrants.Principal(c, mc, exec_ch)
			} else if c.Type() == channels.NPC_CHANNEL {
				//go do something?
			} else if c.Type() == channels.EXEC_CHANNEL {
				//go do something else?
			} else {
				//bad channel
				c.Close()
				continue
			}
		}
	}()
	wg.Wait() //client program ends when the code execution channel ends.
	//TODO(baumanl): figure out definitive closing behavior --> multiple code exec channels?
	logrus.Info("Done waiting")
}
