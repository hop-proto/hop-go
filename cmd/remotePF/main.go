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
	if tcperr != nil {
		//cudsconn.Write([]byte{netproxy.NpcDen})
		logrus.Fatal(tcperr)
	}

	logrus.Infof("Started TCP listener on port: %v", os.Args[1])
	for i := 0; i < 2; i++ {
		cudsconn, err := net.Dial("unix", sock)
		if err != nil {
			logrus.Error("error dialing socket", err)
		}
		logrus.Info("dialed UDS")
		tconn, e := tcpListener.Accept()
		if e != nil {
			cudsconn.Write([]byte{netproxy.NpcDen})
			logrus.Error("error accepting tcp conn")
			return
		}
		logrus.Info("Accepted TCPConn...")
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
	}
}
