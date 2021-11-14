package main

import (
	"os"
	"os/user"

	"github.com/sirupsen/logrus"
)

func main() {
	//set up logging to file
	f, e := os.OpenFile("log.txt", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if e != nil {
		logrus.Error("error opening a.txt", e)
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

	// tcpListener, e := net.Listen("tcp", ":"+parts[0]) //TODO(baumanl): this runs with root privileges which is bad because unprivileged users can forward privileged ports on the server
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
