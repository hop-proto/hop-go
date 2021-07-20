package main

import (
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/channels"
	"zmap.io/portal/exec_channels"
	"zmap.io/portal/transport"
)

func startClient(args []string) {
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

	//Check if this is a principal client process or one that needs to get an AG
	//******GET AUTHORIZATION SOURCE******
	if args[3] == "-k" {
		logrus.Infof("C: Using key-file at %v for auth.", args[4])
		//TODO: actually do this somehow???
	} else if args[3] == "-a" {
		principal = false
		logrus.Infof("C: Initiating AGC Protocol.")
		//TODO: generate keypair and store somehow
		digest := sha3.Sum256([]byte("pubkey")) //don't know if this is correct
		cmd = args[4:]                          //if using authorization grant then perform the action specified in cmd line
		t, e := authgrants.GetAuthGrant(digest, user, addr, cmd)
		if e != nil {
			logrus.Fatalf("C: %v", e)
		}
		logrus.Infof("C: Principal approved request. Deadline: %v", t)
		//TODO: potentially store the deadline somewhere?
	}

	//******ESTABLISH HOP SESSION******
	//TODO: figure out addr format requirements + check for them above
	transportConn, err := transport.Dial("udp", addr, nil) //There seem to be limits on Dial() and addr format
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
	state := exec_channels.MakeRawTerm()
	defer exec_channels.RestoreTerm(state)
	go exec_channels.Client(ch, cmd, &wg)

	//*****START LISTENING FOR INCOMING CHANNEL REQUESTS*****
	for {
		c, e := mc.Accept()
		if e != nil {
			logrus.Fatalf("Error accepting channel: ", e)
		}
		if c.Type() == channels.AGC_CHANNEL && principal {
			go authgrants.Principal(c, mc, state)
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
}
