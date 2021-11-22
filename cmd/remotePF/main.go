package main

import (
	"io"
	"net"
	"os"
	"os/user"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/netproxy"
)

const sock = "@remotesock"

func main() {
	//set up logging to file
	f, e := os.Create("log.txt")
	if e != nil {
		logrus.Error(e)
		return
	}
	if e != nil {
		logrus.Error("error opening log.txt: ", e)
		return
	}
	defer f.Close()
	logrus.SetOutput(f)
	logrus.Info("Starting new run...")
	curUser, err := user.Current()
	if err != nil {
		logrus.Error("issue getting current user in child proc")
		return
	}
	logrus.Infof("Child running as: %v. With UID: %v GID: %v", curUser.Username, curUser.Uid, curUser.Gid)

	tcpListener, tcperr := net.Listen("tcp", ":"+os.Args[1])
	if tcperr != nil {
		cudsconn, err := net.Dial("unix", sock)
		if err != nil {
			logrus.Fatal("error dialing socket", err)
		}
		cudsconn.Write([]byte{netproxy.NpcDen})
		logrus.Fatal(tcperr)
	}
	logrus.Infof("Started TCP listener on port: %v", os.Args[1])

	regchan := make(chan net.Conn)
	go func() {
		logrus.Info("started tcp accept go routine")
		c, err := tcpListener.Accept()
		if err != nil {
			logrus.Error(err)
		}
		logrus.Info("Accepted TCPConn...")
		regchan <- c
	}()

	logrus.Info("Dialed control socket")
	ccconn, _ := net.Dial("unix", "@control")

	controlChan := make(chan byte)
	go func() {
		buf := make([]byte, 1)
		ccconn.Read(buf)
		controlChan <- buf[0]
	}()

	for {
		logrus.Info("entered for loop")
		select {
		case <-controlChan:
			return
		case tconn := <-regchan:
			logrus.Info("got a tconn")
			go func() {
				cudsconn, err := net.Dial("unix", sock)
				if err != nil {
					logrus.Fatal("error dialing socket", err)
				}
				logrus.Info("dialed UDS")

				_, err = cudsconn.Write([]byte{netproxy.NpcConf})
				if err != nil {
					logrus.Error("error writing: ", err)
				}
				logrus.Info("wrote conf")
				go func() {
					io.Copy(cudsconn, tconn)
					cudsconn.Close()
				}()
				io.Copy(tconn, cudsconn)
				tconn.Close()
				go func() {
					c, _ := tcpListener.Accept()
					logrus.Info("Accepted TCPConn...")
					regchan <- c
				}()
			}()
		}
	}
}
