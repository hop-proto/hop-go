package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	ctxio "github.com/jbenet/go-context/io"
	"github.com/sirupsen/logrus"
	"golang.org/x/term"
)

func myCopy(dst io.Writer, src io.Reader, buf []byte, m *sync.Mutex) (written int64, err error) {
	if buf == nil {
		size := 32 * 1024
		if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
			if l.N < 1 {
				size = 1
			} else {
				size = int(l.N)
			}
		}
		buf = make([]byte, size)
	}
	// for {
	// 	m.Lock()
	// 	go func() {
	// 		nr, er := src.Read(buf)
	// 		c <- 1
	// 		if nr > 0 {
	// 			nw, ew := dst.Write(buf[0:nr])
	// 			if nw < 0 || nr < nw {
	// 				nw = 0
	// 				if ew == nil {
	// 					ew = errors.New("errInvalidWrite")
	// 				}
	// 			}
	// 			written += int64(nw)
	// 			if ew != nil {
	// 				err = ew
	// 				return
	// 			}
	// 			if nr != nw {
	// 				err = io.ErrShortWrite
	// 				return
	// 			}
	// 		}
	// 		if er != nil {
	// 			if er != io.EOF {
	// 				err = er
	// 			}
	// 			return
	// 		}
	// 	}()
	// 	select {
	// 	case <- c:
	// 		m.Unlock()	//read something:
	// 	case <- cv: //cond var:
	// 	}

	for {
		m.Lock()
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("errInvalidWrite")
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

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

	// var i interface{} = os.Stdin
	// _, ok := i.(io.WriterTo)
	// logrus.Infof("os.file implements writerto? %v", ok)

	// var j interface{} = transportConn
	// _, ok = j.(io.ReaderFrom)
	// logrus.Infof("tconn implements readerFrom? %v", ok)

	//m := sync.Mutex{}
	//m2 := sync.Mutex{}
	wg := sync.WaitGroup{}
	wg.Add(1)

	ctx, cancel := context.WithCancel(context.Background())
	in := ctxio.NewReader(ctx, os.Stdin)

	go func() {
		//defer wg.Done()
		//myCopy(transportConn, os.Stdin, nil, &m)
		io.Copy(transportConn, in)
	}()

	go func() {
		defer wg.Done()
		//myCopy(os.Stdout, transportConn, nil, &m2)
		io.Copy(os.Stdout, transportConn)

		term.Restore(int(os.Stdin.Fd()), oldState)

	}()

	term.Restore(int(os.Stdin.Fd()), oldState)
	logrus.Info("5 seconds to execute normal commands...")
	term.MakeRaw(int(os.Stdin.Fd()))
	time.Sleep(5 * time.Second)
	term.Restore(int(os.Stdin.Fd()), oldState)
	logrus.Info("Times up! Let's redirect your input...")
	cancel()
	logrus.Info("Cancelled")
	var name string
	fmt.Println("Enter your name: ")
	fmt.Scanln(&name)
	fmt.Println("Hello, ", name)
	logrus.Info("Returning to interactive sess...")
	term.MakeRaw(int(os.Stdin.Fd()))
	ctx, cancel = context.WithCancel(context.Background())
	in = ctxio.NewReader(ctx, os.Stdin)

	go func() {
		//defer wg.Done()
		//myCopy(transportConn, os.Stdin, nil, &m)
		io.Copy(transportConn, in)
	}()

	wg.Wait()
	logrus.Info("all done!")
	// //TODO: should these functions + things from Channels layer have errors?
	// mc := channels.NewMuxer(transportConn, transportConn)
	// go mc.Start()
	// defer mc.Stop()

	// ch, err := mc.CreateChannel(channels.EXEC_CHANNEL)
	// if err != nil {
	// 	logrus.Fatalf("C: error making channel: %v", err)
	// }
	// defer ch.Close()
	// logrus.Infof("Created channel of type: %v", ch.Type())

	// // MakeRaw put the terminal connected to the given file
	// // descriptor into raw mode and returns the previous state
	// // of the terminal so that it can be restored.
	// oldState, e := term.MakeRaw(int(os.Stdin.Fd()))
	// if e != nil {
	// 	logrus.Fatalf("C: error with terminal state: %v", err)
	// }

	// ch.Write(codex.NewexecInitMsg("bash").ToBytes())
	// go func() {
	// 	io.Copy(os.Stdout, ch) //read bytes from ch to os.Stdout
	// 	logrus.Info("Stopped io.Copy(os.Stdout, ch)")
	// }()

	// ctx, cancel := context.WithCancel(context.Background())
	// cr := ctxio.NewReader(ctx, os.Stdin)

	// go io.Copy(ch, cr)

	// time.Sleep(5 * time.Second)

	// term.Restore(int(os.Stdin.Fd()), oldState)
	// cancel()
	// fmt.Println("")
	// i.Run(&i.Interact{
	// 	Questions: []*i.Question{
	// 		{
	// 			Quest: i.Quest{
	// 				Msg: "Allow <someone> to do <something>?",
	// 			},
	// 			Action: func(c i.Context) interface{} {
	// 				val, err := c.Ans().Bool()
	// 				if err != nil {
	// 					return err
	// 				}
	// 				fmt.Println(val)
	// 				return nil
	// 			},
	// 		},
	// 	},
	// })

	// //logrus.Info("restoring pipe to exec channel")
	// oldState, e = term.MakeRaw(int(os.Stdin.Fd()))
	// if e != nil {
	// 	logrus.Fatalf("C: error with terminal state: %v", err)
	// }
	// defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()
	// ctx, cancel = context.WithCancel(context.Background())
	// cr = ctxio.NewReader(ctx, os.Stdin)

	// // r, w = io.Pipe()
	// // go func() {
	// // 	io.Copy(w, os.Stdin)
	// // 	logrus.Info("Stopped io.Copy(w, os.Stdin)")
	// // }()

	// // go func() {
	// // 	io.Copy(ch, r)
	// // 	logrus.Info("Stopped io.Copy(ch, r)")
	// // }()
	// go io.Copy(ch, cr)
	// time.Sleep(5 * time.Second)
	// //logrus.Info("All done now!")
}
