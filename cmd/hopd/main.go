package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"zmap.io/portal/app"
	"zmap.io/portal/config"
	"zmap.io/portal/transport"
)

// Flags holds the command-line flags for hopd.
//
// TODO(dadrian): Should this be in a non-main package?
type Flags struct {
	ConfigPath string
}

func main() {
	logrus.SetLevel(logrus.InfoLevel)

	var fs flag.FlagSet
	f := Flags{}

	var sockAddr string
	fs.StringVar(&sockAddr, "s", app.DefaultHopAuthSocket, "indicates custom sockaddr to use for auth grant")
	fs.StringVar(&f.ConfigPath, "C", "", "path to server config file")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		logrus.Fatalf("%s", err)
		return
	}

	err = config.InitServer(f.ConfigPath)
	if err != nil {
		logrus.Fatalf("error loading config: %s", err)
	}

	sc := config.GetServer()
	vhosts, err := app.NewVirtualHosts(sc, nil, nil)
	if err != nil {
		logrus.Fatalf("unable to parse virtual hosts: %s", err)
	}

	pktConn, err := net.ListenPacket("udp", sc.ListenAddress)
	if err != nil {
		logrus.Fatalf("unable to open socket for address %s: %s", sc.ListenAddress, err)
	}
	udpConn := pktConn.(*net.UDPConn)
	logrus.Infof("listening at %s", udpConn.LocalAddr())

	getCert := func(info transport.ClientHandshakeInfo) (*transport.Certificate, error) {
		if h := vhosts.Match(info.ServerName); h != nil {
			return &h.Certificate, nil
		}
		return nil, fmt.Errorf("%v did not match a host block", info.ServerName)
	}

	tconf := transport.ServerConfig{
		ClientVerify: &transport.VerifyConfig{
			InsecureSkipVerify: true, // Do authorized keys instead
		},
		GetCertificate: getCert,
	}

	underlying, err := transport.NewServer(udpConn, tconf)
	if err != nil {
		logrus.Fatalf("unable to open transport server: %s", err)
	}

	serverConfig := &app.HopServerConfig{
		SockAddr:                 sockAddr,
		MaxOutstandingAuthgrants: 50, // TODO(dadrian): How was this picked? Is this a setting?
	}
	s, err := app.NewHopServer(underlying, serverConfig)
	if err != nil {
		logrus.Fatal(err)
	}
	sch := make(chan os.Signal, 1)
	signal.Notify(sch, os.Interrupt, syscall.SIGTERM) // TODO(dadrian): Does this work on Windows?
	go func() {
		s.Serve()
		sch <- syscall.SIGTERM
	}()
	<-sch
}
