package main

import (
	"io"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/channels"
	"zmap.io/portal/exec_channels"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

func startClient(args []string) {
	//logrus.SetLevel(logrus.DebugLevel)
	logrus.SetLevel(logrus.InfoLevel)
	principal := true
	//******PROCESS ARGUMENTS******
	if len(args) < 5 {
		logrus.Fatal("C: Invalid arguments. Useage: hop user@host:port -k <pathtokey> or hop user@host:port -a <action>.")
	}
	s := strings.SplitAfter(args[2], "@") //TODO: Add support for optional username
	user := s[0][0 : len(s[0])-1]
	addr := s[1]
	cmd := []string{"bash"} //default action for principal is to open an interactive shell
	config := transport.ClientConfig{}
	//TODO: get keypair from file if principal
	config.KeyPair = new(keys.X25519KeyPair)
	config.KeyPair.Generate()
	logrus.Infof("Client generated(39): %v", config.KeyPair.Public.String())
	reader, writer := io.Pipe()
	_, writer2 := io.Pipe()
	w := io.MultiWriter(writer, writer2)
	go func() {
		io.Copy(w, os.Stdin)
	}()

	//Check if this is a principal client process or one that needs to get an AG
	//******GET AUTHORIZATION SOURCE******
	if args[3] == "-k" {
		logrus.Infof("C: Using key-file at %v for auth.", args[4])
		//TODO: actually do this somehow???
	} else if args[3] == "-a" {
		principal = false
		logrus.Infof("C: Initiating AGC Protocol.")
		cmd = args[4:] //if using authorization grant then perform the action specified in cmd line
		t, e := authgrants.GetAuthGrant(config.KeyPair.Public, user, addr, cmd)
		if e != nil {
			logrus.Fatalf("C: %v", e)
		}
		logrus.Infof("C: Principal approved request. Deadline: %v", t)
		//TODO: potentially store the deadline somewhere?
	}

	//******ESTABLISH HOP SESSION******
	//TODO: figure out addr format requirements + check for them above
	transportConn, err := transport.Dial("udp", addr, &config) //There seem to be limits on Dial() and addr format
	if err != nil {
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	err = transportConn.Handshake()
	if err != nil {
		logrus.Fatalf("C: Issue with handshake: %v", err)
	}
	//TODO: should these functions + things from Channels layer have errors?
	mc := channels.NewMuxer(transportConn, transportConn)
	go mc.Start()
	defer mc.Stop()

	//*****RUN COMMAND (BASH OR AG ACTION)*****
	logrus.Infof("Performing action: %v", cmd)
	ch, _ := mc.CreateChannel(channels.EXEC_CHANNEL)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go exec_channels.Client(ch, cmd, &wg, reader)

	//*****START LISTENING FOR INCOMING CHANNEL REQUESTS*****
	go func() {
		for {
			c, e := mc.Accept()
			if e != nil {
				logrus.Fatalf("Error accepting channel: ", e)
			}
			logrus.Infof("ACCEPTED NEW CHANNEL of TYPE: %v", c.Type())
			if c.Type() == channels.AGC_CHANNEL && principal {
				go authgrants.Principal(c, mc)
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
	wg.Wait()
	logrus.Info("Done waiting")
}
