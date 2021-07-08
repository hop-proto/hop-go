package main

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/channels"
	"zmap.io/portal/exec"
	"zmap.io/portal/transport"
)

func startClient() {
	addr := "127.0.0.1:7777"

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

	ch, err := mc.CreateChannel(channels.EXEC_CHANNEL)
	if err != nil {
		logrus.Fatalf("C: error making channel: %v", err)
	}
	logrus.Infof("Created channel of type: %v", ch.Type())

	ch.Write(exec.NewExecInitMsg("echo hello world").ToBytes())

	l := make([]byte, 1)
	ch.Read(l)
	logrus.Infof("Expecting %v bytes", int(l[0]))
	buf := make([]byte, int(l[0]))
	n, _ := ch.Read(buf)
	logrus.Infof("Rec: %v", n)

	fmt.Println(strings.TrimSpace(string(buf)))

	ch.Close()
}
