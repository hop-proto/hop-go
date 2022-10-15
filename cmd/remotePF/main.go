package main

import (
	"io"
	"net"
	"os"
	"os/user"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/netproxy"
	"hop.computer/hop/portforwarding"
)

func main() {
	arg := os.Args[1]
	fwdStruct := portforwarding.Fwd{
		Listensock:        false,
		Connectsock:       false,
		Listenhost:        "",
		Listenportorpath:  "",
		Connecthost:       "",
		Connectportorpath: "",
	}
	portforwarding.ParseForward(arg, &fwdStruct)

	contentSockAddr := "@content" + fwdStruct.Listenportorpath
	controlSockAddr := "@control" + fwdStruct.Listenportorpath
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
	var tcpListener net.Listener
	if !fwdStruct.Listensock {
		addr := net.JoinHostPort(fwdStruct.Listenhost, fwdStruct.Listenportorpath)
		tcpListener, err = net.Listen("tcp", addr)
	} else {
		tcpListener, err = net.Listen("unix", fwdStruct.Listenportorpath)
	}
	if err != nil {
		logrus.Error(err)
		control, err := net.Dial("unix", controlSockAddr)
		if err != nil {
			logrus.Error("error dialing control sock", err)
			return
		}
		logrus.Info("Dialed control socket")
		control.Write([]byte{netproxy.NpcDen})
		control.Close()
		logrus.Fatal()
	}

	defer tcpListener.Close()
	logrus.Infof("Started TCP listener on port/path: %v", fwdStruct.Listenportorpath)

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

	control, err := net.Dial("unix", controlSockAddr)
	if err != nil {
		logrus.Error("error dialing control sock", err)
		return
	}
	logrus.Info("Dialed control socket")
	control.Write([]byte{netproxy.NpcConf})
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
				cudsconn, err := net.Dial("unix", contentSockAddr)
				if err != nil {
					logrus.Fatal("error dialing socket", err)
				}
				logrus.Info("dialed UDS")
				go func() {
					n, _ := io.Copy(cudsconn, tconn)
					cudsconn.Close()
					logrus.Debugf("Copied %v bytes from tconn to cudsconn", n)
					logrus.Info("tconn ended")
				}()
				n, _ := io.Copy(tconn, cudsconn)
				tconn.Close()
				logrus.Debugf("Copied %v bytes from cudsconn to tconn", n)
			}()
		}
	}
}
