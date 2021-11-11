package main

import (
	"flag"
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/app"
)

func main() {
	logrus.Infof("Hosting hop server daemon")

	var fs flag.FlagSet

	var sockAddr string
	fs.StringVar(&sockAddr, "s", app.DefaultHopAuthSocket, "indicates custom sockaddr to use for auth grant")

	var port string
	fs.StringVar(&port, "p", app.DefaultHopPort, "port to listen on")

	hostname, _ := os.Hostname()
	fs.StringVar(&hostname, "h", hostname, "hostname/ip addr to listen on")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		return
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
