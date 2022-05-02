package main

import (
	"net"
	"net/http"

	"github.com/sirupsen/logrus"

	"zmap.io/portal/agent"
	"zmap.io/portal/common"
)

func main() {
	// logrus.SetLevel(logrus.InfoLevel)
	d := agent.Data{}
	err := d.Init()
	if err != nil {
		logrus.Fatalf("unable to load agent data: %s", err)
	}
	s := agent.New(&d)
	address := net.JoinHostPort("localhost", common.DefaultAgentPortString)
	sock, err := net.Listen("tcp", address)
	if err != nil {
		logrus.Fatalf("unable to open tcp socket %s: %s", address, err)
	}
	logrus.Infof("listening on %s", sock.Addr().String())
	http.Serve(sock, s)
}
