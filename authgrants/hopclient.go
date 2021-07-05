package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"zmap.io/portal/channels"
	"zmap.io/portal/transport"
)

//DEATH BY PARSING....AAAAAHHH
func buildIntentRequest(sha3id [32]byte, action string, user string, addr string) []byte {

	/*These aren't currently part of the protocol
	but I feel like they are important?*/
	// client := os.Current().Username
	// clienthostname, err := os.Hostname()

	//Set the Msg type field
	request := []byte{INTENT_REQUEST}

	//Add the SHA3 Client Identifier
	request = append(request, sha3id[:]...)

	//TODO: Why is there a separate port field?
	//parse addr into host:port and port
	portstr := ""
	if strings.Contains(addr, ":") {
		i := strings.Index(addr, ":")
		portstr = addr[i+1:]
	}
	//TODO: make a correct sni? Should this also include desired user on remote server?
	// Figure out what what address to use (copied/modified from Davids gonet.go file)
	throwaway, err := net.Dial("udp", addr) //addr needs to be of form host:port
	if err != nil {
		logrus.Fatal("Failed to figure out address. Check addr is in <host>:<port> format.")
	}
	remoteAddr := throwaway.RemoteAddr()
	throwaway.Close()

	sniinfo := []byte(remoteAddr.String())
	if len(sniinfo) > 256 {
		logrus.Fatalf("Invalid SNI. Length exceeded 256 bytes")
	}
	sni := [256]byte{}
	for i, b := range sniinfo {
		sni[i] = b
	}
	//Add the SNI
	request = append(request, sni[:]...)

	//TODO: Is this necessary? Isn't this included in SNI? Can definitely be done cleaner if necessary
	//Add the PORT number
	if portstr != "" {
		MAXPORTNUMBER := 65535
		port, _ := strconv.Atoi(portstr)
		if port > MAXPORTNUMBER {
			logrus.Fatal("port number out of range")
		}
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(port))
		request = append(request, b...)
	} else {
		request = append(request, make([]byte, 2)...)
	}

	//Add the Channel Type (how is this determined...?/Why necessary...?)
	request = append(request, byte(0))

	//Reserved byte
	request = append(request, byte(0))

	//Associated data (action)
	request = append(request, []byte(action)...)

	return request

}

func getAuthGrant(intent []byte) bool {
	c, err := net.Dial("unix", "echo1.sock")
	if err != nil {
		logrus.Fatal(err)
	}
	defer c.Close()
	logrus.Info("C2: CONNECTED TO UDS: [%v]", c.RemoteAddr().String())
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
		logrus.Fatal("Invalid arguments. Useage: hop user@host:port -k <pathtokey> or hop user@host:port -a <action>")
	}
	//parse args
	s := strings.SplitAfter(args[2], "@")
	user := s[0][0 : len(s[0])-1]
	addr := s[1]
	//Check if this is a principal client process or one that needs to get an AG
	if args[3] == "-k" {
		logrus.Infof("Principal: will use key-file at %v for auth.", args[4])
		//TODO: actually do this somehow???
	} else if args[3] == "-a" {
		logrus.Infof("Not Principal: will initiate AGC Protocol.")
		//generate keypair
		pubkey := "public key"              //need to actually generate a key (probably using David's stuff...?)
		hash := sha3.Sum256([]byte(pubkey)) //don't know if this is correct
		intent := buildIntentRequest(hash, args[4], user, addr)
		logrus.Infof("INTENT_REQUEST: %v", string(intent))
		if !getAuthGrant(intent) {
			logrus.Fatal("Principal denied request.")
		}
	}

	transportConn, err := transport.Dial("udp", addr, nil) //There seem to be limits on Dial() and addr format

	if err != nil {
		logrus.Fatalf("error dialing server: %v", err)
	}
	err = transportConn.Handshake()
	if err != nil {
		logrus.Fatalf("issue with handshake: %v", err)
	}
	mc := channels.NewMuxer(transportConn, transportConn)
	go mc.Start()
	defer mc.Stop()
	logrus.Info("STARTED MUXER")

	if p == "1" {
		channel, err := mc.CreateChannel(1 << 8)
		if err != nil {
			logrus.Fatalf("error making channel: %v", err)
		}
		logrus.Infof("CREATED CHANNEL")
		s := []byte("INTENT_REQUEST")
		//TODO: make actual byte message type

		_, err = channel.Write(s)
		if err != nil {
			logrus.Fatalf("error writing to channel: %v", err)
		}
		logrus.Infof("WROTE INTENT")

		agc, err := mc.Accept()
		if err != nil {
			logrus.Fatalf("issue accepting channel: %v", err)
		}
		logrus.Info("ACCEPTED NEW CHANNEL (AGC)")
		agc_buf := make([]byte, 14)
		n, err := agc.Read(agc_buf)
		if err != nil {
			logrus.Fatalf("issue reading from channel: %v", err)
		}
		if string(agc_buf[0:n]) == "INTENT_REQUEST" {
			logrus.Info("PRINCIPAL REC: INTENT_REQUEST")
			logrus.Info("PROMPTING USER")
			fmt.Printf("Allow user to do %v? Enter yes or no\n", "INTENT_REQUEST")
			var resp string
			fmt.Scanln(&resp) //TODO: make sure this is safe/sanitize input/make this a popup instead.
			if resp == "yes" {
				logrus.Info("USER CONFIRMED INTENT_REQUEST. CONTACTING S2...") //TODO: ACTUALLY DO THE NPC THING
				logrus.Info("PRETENDING S2 SAID YES")
				s := []byte("INTENT_CONFIRMATION")
				//TODO: make actual byte message type

				_, err = agc.Write(s)
				if err != nil {
					logrus.Fatalf("error writing to agc: %v", err)
				}
				logrus.Infof("WROTE INTENT_CONFIRMATION")
			}
		} else {
			logrus.Info("INTENT DENIED")
		}

		buf := make([]byte, 50) //fix buffer size
		n, err = channel.Read(buf)
		if err != nil {
			logrus.Fatalf("issue reading from channel: %v", err)
		}
		if string(buf[0:n]) == "yes" {
			logrus.Info("INTENT APPROVED")
		} else {
			logrus.Info("INTENT DENIED")
		}

		err = channel.Close()
		if err != nil {
			fmt.Printf("error closing channel: %v", err)
		}
	} else if p == "2" {
		logrus.Infof("c2 connected to %v", addr)
	}

	//infinite loop so the client program doesn't quit
	//otherwise client quits before server can read data
	//TODO: Figure out how to check if the other side closed channel

	for {
	}

}
