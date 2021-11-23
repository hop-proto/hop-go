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
	f, e := os.Create("/tmp/log.txt")
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

	//set up tcplistener on remote port
	tcpListener, tcperr := net.Listen("tcp", ":"+os.Args[1])
	if tcperr != nil {
		cudsconn, err := net.Dial("unix", sock)
		if err != nil {
			logrus.Fatal("error dialing socket", err)
		}
		cudsconn.Write([]byte{netproxy.NpcDen})
		logrus.Fatal(tcperr)
	}
	defer tcpListener.Close()
	logrus.Infof("Started TCP listener on port: %v", os.Args[1])

	//all accepted tcp conns will go to this go chan
	regchan := make(chan net.Conn)
	go func() {
		logrus.Info("started tcp accept go routine")
		for {
			c, err := tcpListener.Accept() //listen for first tcpconn
			if err != nil {
				logrus.Error(err)
			}
			logrus.Info("Accepted TCPConn...")
			regchan <- c
		}
	}()

	control, err := net.Dial("unix", "@control")
	if err != nil {
		logrus.Error("error dialing control sock", err)
		return
	}
	logrus.Info("Dialed control socket")
	defer control.Close()

	controlChan := make(chan byte)
	go func() {
		buf := make([]byte, 1)
		control.Read(buf)
		controlChan <- buf[0]
	}()

	for {
		select {
		case <-controlChan: //if parent process sends any bytes over control, end process
			logrus.Info("closing")
			return
		case tconn := <-regchan:
			go func() {
				cudsconn, err := net.Dial("unix", sock)
				if err != nil {
					logrus.Fatal("error dialing socket", err)
				}
				logrus.Info("dialed UDS")
				go func() {
					n, _ := io.Copy(cudsconn, tconn)
					cudsconn.Close()
					logrus.Infof("Copied %v bytes from tconn to cudsconn", n)
					logrus.Info("tconn ended")
				}()
				n, _ := io.Copy(tconn, cudsconn)
				tconn.Close()
				logrus.Infof("Copied %v bytes from cudsconn to tconn", n)
			}()
		}
	}
}
