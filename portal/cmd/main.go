package main

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"zmap.io/portal"
)

func main() {
	fmt.Println("portal!")
	logrus.SetLevel(logrus.DebugLevel)
	c, err := net.Dial("tcp", "localhost:9720")
	if err != nil {
		logrus.Fatalf("could not make socket: %s", err)
	}
	p := portal.Client(c, nil)
	err = p.Handshake()
	if err != nil {
		logrus.Fatalf("could not handshake: %s", err)
	}
}
