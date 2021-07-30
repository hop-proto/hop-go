package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	ctxio "github.com/jbenet/go-context/io"
	"github.com/sirupsen/logrus"
	i "github.com/tockins/interact"
	"golang.org/x/term"
	"zmap.io/portal/channels"
	"zmap.io/portal/codex"
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

	// MakeRaw put the terminal connected to the given file
	// descriptor into raw mode and returns the previous state
	// of the terminal so that it can be restored.
	oldState, e := term.MakeRaw(int(os.Stdin.Fd()))
	if e != nil {
		logrus.Fatalf("C: error with terminal state: %v", err)
	}

	ch.Write(codex.NewExecInitMsg("bash").ToBytes())
	go func() {
		io.Copy(os.Stdout, ch) //read bytes from ch to os.Stdout
		logrus.Info("Stopped io.Copy(os.Stdout, ch)")
	}()

	r, w := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	cr := ctxio.NewReader(ctx, os.Stdin)

	go func() {
		io.Copy(w, cr)
		//logrus.Info("Stopped io.Copy(w, os.Stdin)")
	}()

	go func() {
		io.Copy(ch, r)
		//logrus.Info("Stopped io.Copy(ch, r)")
	}()

	time.Sleep(5 * time.Second)

	term.Restore(int(os.Stdin.Fd()), oldState)
	w.Close()
	r.Close()
	cancel()
	fmt.Println("")
	i.Run(&i.Interact{
		Questions: []*i.Question{
			{
				Quest: i.Quest{
					Msg: "Allow <someone> to do <something>?",
				},
				Action: func(c i.Context) interface{} {
					val, err := c.Ans().Bool()
					if err != nil {
						return err
					}
					fmt.Println(val)
					return nil
				},
			},
		},
	})

	//logrus.Info("restoring pipe to exec channel")
	oldState, e = term.MakeRaw(int(os.Stdin.Fd()))
	if e != nil {
		logrus.Fatalf("C: error with terminal state: %v", err)
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	r, w = io.Pipe()
	go func() {
		io.Copy(w, os.Stdin)
		logrus.Info("Stopped io.Copy(w, os.Stdin)")
	}()

	go func() {
		io.Copy(ch, r)
		logrus.Info("Stopped io.Copy(ch, r)")
	}()
	time.Sleep(5 * time.Second)
	//logrus.Info("All done now!")
}
