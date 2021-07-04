package main

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/channels"
	"zmap.io/portal/transport"
)

func reader(r net.Conn, finished chan bool, intent string) {
	defer func() {
		finished <- true
	}()
	logrus.Infof("C2: Connected to server [%s]", r.RemoteAddr().Network())

	//send intent
	r.Write([]byte(intent))

	buf := make([]byte, 19)
	n, err := r.Read(buf)
	if err != nil {
		logrus.Fatal(err)
		return
	}
	logrus.Infof("C2: Client got: %v", string(buf[0:n]))
	if string(buf[0:n]) == "INTENT_CONFIRMATION" {
		logrus.Info("STARTING HOP SESSION WITH S2...")
	}
}

func startClientTwo() {
	c, err := net.Dial("unix", "echo1.sock")
	if err != nil {
		logrus.Fatal(err)
	}
	defer c.Close()
	logrus.Info("C2: CONNECTED TO UDS")

	finished := make(chan bool)
	go reader(c, finished, "INTENT_REQUEST") //TODO: Actually pass the intent request through to here

	<-finished
}

func startClient(p string) {
	logrus.SetLevel(logrus.InfoLevel)
	if p == "2" {
		startClientTwo()
	}
	//TODO: accept args to dial custom address + user?
	addr := "127.0.0.1:8888"
	if p == "2" {
		addr = "127.0.0.1:9999"
	}
	transportConn, err := transport.Dial("udp", addr, nil)

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
