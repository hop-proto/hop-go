package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/term"
)

func startClient(p string) {

	addr := "127.0.0.1:" + p

	//******ESTABLISH HOP SESSION******
	//TODO: figure out addr format requirements + check for them above
	transportConn, err := net.Dial("tcp", addr) //There seem to be limits on Dial() and addr format
	if err != nil {
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	logrus.Info("CONNECTED")
	oldState, e := term.MakeRaw(int(os.Stdin.Fd()))
	if e != nil {
		logrus.Fatalf("C: error with terminal state: %v", err)
	}
	r, w := io.Pipe()

	redir := false
	go func() {
		_, e := io.Copy(os.Stdout, transportConn)
		logrus.Error("1", e)
	}()

	go func() {
		for {
			p := make([]byte, 1)
			_, _ = os.Stdin.Read(p)
			if redir {
				w.Write(p)
			} else {
				transportConn.Write(p)
			}
		}

	}()

	term.Restore(int(os.Stdin.Fd()), oldState)
	logrus.Info("Regular copying for 5 sec...")
	term.MakeRaw(int(os.Stdin.Fd()))
	time.Sleep(5 * time.Second)
	term.Restore(int(os.Stdin.Fd()), oldState)
	logrus.Info("Switching...")
	redir = true
	fmt.Println("Enter your name: ")
	var name string
	scanner := bufio.NewScanner(r)
	scanner.Scan()
	name = scanner.Text()
	//logrus.Error(e)
	fmt.Println("Your name is: ", name)
	logrus.Info("Going back to reg copying for 5 sec...")
	term.MakeRaw(int(os.Stdin.Fd()))
	redir = false
	time.Sleep(5 * time.Second)
	term.Restore(int(os.Stdin.Fd()), oldState)
}

// var i interface{} = os.Stdin
// _, ok := i.(io.WriterTo)
// logrus.Infof("os.file implements writerto? %v", ok)

// var j interface{} = transportConn
// _, ok = j.(io.ReaderFrom)
// logrus.Infof("tconn implements readerFrom? %v", ok)

//m := sync.Mutex{}
//m2 := sync.Mutex{}
// wg := sync.WaitGroup{}
// wg.Add(1)

// ctx, cancel := context.WithCancel(context.Background())
// in := ctxio.NewReader(ctx, os.Stdin)

// go func() {
// 	//defer wg.Done()
// 	//myCopy(transportConn, os.Stdin, nil, &m)
// 	io.Copy(transportConn, in)
// }()

// go func() {
// 	defer wg.Done()
// 	//myCopy(os.Stdout, transportConn, nil, &m2)
// 	io.Copy(os.Stdout, transportConn)

// 	term.Restore(int(os.Stdin.Fd()), oldState)

// }()

// term.Restore(int(os.Stdin.Fd()), oldState)
// logrus.Info("5 seconds to execute normal commands...")
// term.MakeRaw(int(os.Stdin.Fd()))
// time.Sleep(5 * time.Second)
// term.Restore(int(os.Stdin.Fd()), oldState)
// logrus.Info("Times up! Let's redirect your input...")
// cancel()
// logrus.Info("Cancelled")
// var name string
// fmt.Println("Enter your name: ")
// fmt.Scanln(&name)
// fmt.Println("Hello, ", name)
// logrus.Info("Returning to interactive sess...")
// term.MakeRaw(int(os.Stdin.Fd()))
// ctx, cancel = context.WithCancel(context.Background())
// in = ctxio.NewReader(ctx, os.Stdin)

// go func() {
// 	//defer wg.Done()
// 	//myCopy(transportConn, os.Stdin, nil, &m)
// 	io.Copy(transportConn, in)
// }()

// wg.Wait()
// logrus.Info("all done!")
// // //TODO: should these functions + things from Channels layer have errors?
// // mc := channels.NewMuxer(transportConn, transportConn)
// // go mc.Start()
// // defer mc.Stop()

// // ch, err := mc.CreateChannel(channels.EXEC_CHANNEL)
// // if err != nil {
// // 	logrus.Fatalf("C: error making channel: %v", err)
// // }
// // defer ch.Close()
// // logrus.Infof("Created channel of type: %v", ch.Type())

// // // MakeRaw put the terminal connected to the given file
// // // descriptor into raw mode and returns the previous state
// // // of the terminal so that it can be restored.
// // oldState, e := term.MakeRaw(int(os.Stdin.Fd()))
// // if e != nil {
// // 	logrus.Fatalf("C: error with terminal state: %v", err)
// // }

// // ch.Write(codex.NewexecInitMsg("bash").ToBytes())
// // go func() {
// // 	io.Copy(os.Stdout, ch) //read bytes from ch to os.Stdout
// // 	logrus.Info("Stopped io.Copy(os.Stdout, ch)")
// // }()

// // ctx, cancel := context.WithCancel(context.Background())
// // cr := ctxio.NewReader(ctx, os.Stdin)

// // go io.Copy(ch, cr)

// // time.Sleep(5 * time.Second)

// // term.Restore(int(os.Stdin.Fd()), oldState)
// // cancel()
// // fmt.Println("")
// // i.Run(&i.Interact{
// // 	Questions: []*i.Question{
// // 		{
// // 			Quest: i.Quest{
// // 				Msg: "Allow <someone> to do <something>?",
// // 			},
// // 			Action: func(c i.Context) interface{} {
// // 				val, err := c.Ans().Bool()
// // 				if err != nil {
// // 					return err
// // 				}
// // 				fmt.Println(val)
// // 				return nil
// // 			},
// // 		},
// // 	},
// // })

// // //logrus.Info("restoring pipe to exec channel")
// // oldState, e = term.MakeRaw(int(os.Stdin.Fd()))
// // if e != nil {
// // 	logrus.Fatalf("C: error with terminal state: %v", err)
// // }
// // defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()
// // ctx, cancel = context.WithCancel(context.Background())
// // cr = ctxio.NewReader(ctx, os.Stdin)

// // // r, w = io.Pipe()
// // // go func() {
// // // 	io.Copy(w, os.Stdin)
// // // 	logrus.Info("Stopped io.Copy(w, os.Stdin)")
// // // }()

// // // go func() {
// // // 	io.Copy(ch, r)
// // // 	logrus.Info("Stopped io.Copy(ch, r)")
// // // }()
// // go io.Copy(ch, cr)
// // time.Sleep(5 * time.Second)
// // //logrus.Info("All done now!")
