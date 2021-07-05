package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

//go run *.go => run hopclient.go
//go run *.go -hopd => start hop server

//If on principal: hop user@host:port -k <pathtokey>
//If on intermediate: hop user@host:port -a <action>

func main() {
	if os.Args[1] == "hop" {
		logrus.Infof("Starting hop client")
		startClient(os.Args)
	} else if os.Args[1] == "hopd" {
		fmt.Println("Hosting hop server daemon")
		serve(os.Args) //start "hop server daemon process"
	} else {
		logrus.Fatal("Unrecognized command")
	}
}
