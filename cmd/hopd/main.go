package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/app"
)

// must run with privileged user or with sudo at the moment
// ./hopd 			--> starts server on <hostname>:7777
// ./hopd <port> 	--> starts server on <hostname>:<port>

// ./hopd local 		--> starts server on <localhost>:7777
// ./hopd local <port> 	--> starts server on <localhost>:<port>

func main() {
	logrus.Infof("Hosting hop server daemon")
	hostname, _ := os.Hostname()
	port := app.DefaultHopPort
	sockAddr := app.DefaultHopAuthSocket
	if len(os.Args) > 1 && os.Args[1] == "local" {
		hostname = "localhost"
		if len(os.Args) > 2 {
			port = os.Args[2]
		}
	} else if len(os.Args) > 1 {
		port = os.Args[1]
	}

	tconf, _ := app.NewTestServerConfig(app.TestDataPathPrefixDef)
	serverConfig := &app.HopServerConfig{
		Port:                     port,
		Host:                     hostname,
		SockAddr:                 sockAddr,
		TransportConfig:          tconf,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := app.NewHopServer(serverConfig)
	if err != nil {
		logrus.Fatal(err)
	}
	s.Serve() //starts transport layer server, authgrant server, and listens for hop conns
}
