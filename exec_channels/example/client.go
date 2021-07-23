package main

import (
	"sync"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/channels"
	"zmap.io/portal/exec_channels"
	"zmap.io/portal/transport"
)

func startClient(p string) {
	addr := "127.0.0.1:" + p

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
	defer ch.Close()
	logrus.Infof("Created channel of type: %v", ch.Type())

	// // MakeRaw put the terminal connected to the given file
	// // descriptor into raw mode and returns the previous state
	// // of the terminal so that it can be restored.
	// oldState, e := term.MakeRaw(int(os.Stdin.Fd()))
	// if e != nil {
	// 	logrus.Fatalf("C: error with terminal state: %v", err)
	// }
	// defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	// ch.Write(exec_channels.NewExecInitMsg("bash").ToBytes())
	// r, w := io.Pipe()
	// go func() {
	// 	io.Copy(os.Stdout, ch) //read bytes from ch to os.Stdout
	// 	w.Close()
	// }()
	// go func() {
	// 	io.Copy(w, os.Stdin)
	// }()
	// io.Copy(ch, r)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go exec_channels.Client(ch, []string{"bash"}, &wg)
	wg.Wait()
}
