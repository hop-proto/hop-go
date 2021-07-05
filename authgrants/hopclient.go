package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"zmap.io/portal/channels"
	"zmap.io/portal/transport"
)

func getAuthGrant(intent []byte) bool {
	c, err := net.Dial("unix", "echo1.sock")
	if err != nil {
		logrus.Fatal(err)
	}
	defer c.Close()
	logrus.Infof("C2: CONNECTED TO UDS: [%v]", c.RemoteAddr().String())
	c.Write(intent)

	buf := make([]byte, 19)
	n, err := c.Read(buf)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("C2: Client got: %v", string(buf[0:n]))
	return string(buf[0:n]) == "INTENT_CONFIRMATION"
}

func startClient(args []string) {
	logrus.SetLevel(logrus.InfoLevel)
	if len(args) != 5 {
		logrus.Fatal("C: Invalid arguments. Useage: hop user@host:port -k <pathtokey> or hop user@host:port -a <action>")
	}
	//parse args
	s := strings.SplitAfter(args[2], "@")
	user := s[0][0 : len(s[0])-1]
	addr := s[1]
	//Check if this is a principal client process or one that needs to get an AG
	if args[3] == "-k" {
		logrus.Infof("C: Using key-file at %v for auth.", args[4])
		//TODO: actually do this somehow???
	} else if args[3] == "-a" {
		logrus.Infof("C: Initiating AGC Protocol.")
		//generate keypair
		pubkey := "public key"              //need to actually generate a key (probably using David's stuff...?)
		hash := sha3.Sum256([]byte(pubkey)) //don't know if this is correct
		intent := BuildIntentRequest(hash, args[4], user, addr)
		if !getAuthGrant(intent.ToByteSlice()) {
			logrus.Fatal("C: Principal denied request.")
		}
	}

	transportConn, err := transport.Dial("udp", addr, nil) //There seem to be limits on Dial() and addr format

	if err != nil {
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	err = transportConn.Handshake()
	if err != nil {
		logrus.Fatalf("C: issue with handshake: %v", err)
	}
	mc := channels.NewMuxer(transportConn, transportConn)
	go mc.Start()
	defer mc.Stop()

	//TODO: Either start interactive shell with server 2 or execute Auth grant command

	if args[3] == "-k" { //temporary way to allow Principal to get server to start intent request process
		channel, err := mc.CreateChannel(1 << 8)
		if err != nil {
			logrus.Fatalf("C: error making channel: %v", err)
		}
		s := []byte("INTENT_REQUEST")
		//THIS JUST TRIGGERS THE SERVER TO SPAWN A CLIENT THAT WILL USE AGC PROTOCOL

		_, err = channel.Write(s)
		if err != nil {
			logrus.Fatalf("C: error writing to channel: %v", err)
		}
		logrus.Infof("C: Told Server 1 to hop to Server 2 (PLACEHOLDER FOR BASH)")

		agc, err := mc.Accept()
		if err != nil {
			logrus.Fatalf("C: issue accepting channel: %v", err)
		}
		logrus.Info("C: ACCEPTED NEW CHANNEL (AGC)")
		agc_buf := make([]byte, MIN_INTENT_REQUEST_HEADER_LENGTH)
		n, err := agc.Read(agc_buf)
		if err != nil {
			logrus.Fatalf("C: issue reading from channel: %v", err)
		}
		if agc_buf[0] == INTENT_REQUEST {
			logrus.Info("C: PRINCIPAL REC: INTENT_REQUEST")
			//req, e := BytesToIntentRequest(agc_buf[0:n])
			fmt.Printf("Allow user to do %v? Enter yes or no\n", "INTENT_REQUEST")
			var resp string
			fmt.Scanln(&resp) //TODO: make sure this is safe/sanitize input/make this a popup instead.
			if resp == "yes" {
				logrus.Info("C: USER CONFIRMED INTENT_REQUEST. CONTACTING S2...") //TODO: ACTUALLY DO THE NPC THING
				logrus.Info("C: PRETENDING S2 SAID YES")
				s := []byte("INTENT_CONFIRMATION")
				//TODO: make actual byte message type

				_, err = agc.Write(s)
				if err != nil {
					logrus.Fatalf("C: error writing to agc: %v", err)
				}
				logrus.Infof("C: WROTE INTENT_CONFIRMATION")
			}
		} else {
			logrus.Info("C: INTENT DENIED")
		}

		buf := make([]byte, 50) //fix buffer size
		n, err = channel.Read(buf)
		if err != nil {
			logrus.Fatalf("C: issue reading from channel: %v", err)
		}
		if string(buf[0:n]) == "yes" {
			logrus.Info("C: INTENT APPROVED")
		} else {
			logrus.Info("C: INTENT DENIED")
		}

		err = channel.Close()
		if err != nil {
			fmt.Printf("C: error closing channel: %v", err)
		}
	} else if args[3] == "-a" {
		logrus.Infof("C: c2 connected to %v", addr)
	}

	//infinite loop so the client program doesn't quit
	//otherwise client quits before server can read data
	//TODO: Figure out how to check if the other side closed channel

	for {
	}

}
