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

	// cudsconn, err := net.Dial("unix", sock)
	// if err != nil {
	// 	logrus.Error("error dialing socket", err)
	// }

	tcpListener, tcperr := net.Listen("tcp", ":"+os.Args[1])

	logrus.Infof("Started TCP listener on port: %v", os.Args[1])
	for {
		cudsconn, err := net.Dial("unix", sock)
		if err != nil {
			logrus.Error("error dialing socket", err)
		}
		if tcperr != nil {
			cudsconn.Write([]byte{netproxy.NpcDen})
			logrus.Fatal(e)
		}
		tconn, e := tcpListener.Accept()
		if e != nil {
			cudsconn.Write([]byte{netproxy.NpcDen})
			logrus.Error("error accepting tcp conn")
			return
		}
		logrus.Info("Accepted TCPConn...")
		defer tconn.Close()
		cudsconn.Write([]byte{netproxy.NpcConf})
		go func() {
			io.Copy(cudsconn, tconn)
			cudsconn.Close()
		}()
		io.Copy(tconn, cudsconn)
	}
}
