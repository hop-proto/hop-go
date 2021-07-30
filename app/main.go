package main

import (
	"os"

	"github.com/sirupsen/logrus"
)

//If on principal: hop user@host:port -k <pathtokey>
//If on intermediate: hop user@host:port -a <action>

//Demo:
//principal: go run *.go hop user@127.0.0.1:8888 -k path
//server1: go run *.go hopd 1
//server2: go run *.go hopd 2

func main() {
	if os.Args[1] == "hop" {
		logrus.Infof("Starting hop client")
		client(os.Args)
	} else if os.Args[1] == "hopd" {
		logrus.Infof("Hosting hop server daemon")
		serve(os.Args) //start "hop server daemon process"
	} else {
		logrus.Fatal("Unrecognized command")
	}
}
