package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

//go run *.go => run hopclient.go
//go run *.go -hopd => start hop server

func main() {
	if os.Args[1] == "hop" && len(os.Args) > 2 {
		logrus.Infof("Starting hop client")
		startClient(os.Args[2])
	} else if os.Args[1] == "hopd" && len(os.Args) > 2 {
		fmt.Println("Hosting hop server daemon")
		serve(os.Args) //start "hop server daemon process"
	}
}
