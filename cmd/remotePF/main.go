package main

import (
	"errors"
	"net"
	"os"
	"os/user"

	"github.com/sirupsen/logrus"
)

func main() {
	//set up logging to file
	_, err := os.Stat("log.txt")
	if errors.Is(err, os.ErrNotExist) {
		f, e := os.Create("log.txt")
		if e != nil {
			logrus.Error(e)
			return
		}
		f.Close()
	}
	f, e := os.OpenFile("log.txt", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
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
	logrus.Infof("Will start TCP listener on port: %v", os.Args[1])

	tcpListener, e := net.Listen("tcp", ":"+os.Args[1])
	if e != nil {
		logrus.Fatal(e)
	}
	tcpListener.Close()
	// if e != nil {
	// 	logrus.Error("Issue listening on requested port")
	// 	npTube.Write([]byte{NpcDen})
	// 	return
	// }
	// tconn, e := tcpListener.Accept() //TODO(baumanl): should this be in a loop? how does SSH do it?
	// if e != nil {
	// 	logrus.Error("Issue accepting conn on remote port")
	// 	npTube.Write([]byte{NpcDen})
	// 	return
	// }
	// npTube.Write([]byte{NpcConf})
	// //could net.Pipe() be useful here?
	// go func() {
	// 	//Handles all traffic from principal to server 2
	// 	io.Copy(tconn, npTube)
	// }()
	// //handles all traffic from server 2 back to principal
	// io.Copy(npTube, tconn)

}
