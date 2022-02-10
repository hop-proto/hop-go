package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/app"
	"zmap.io/portal/transport"
)

// Flags holds the command-line flags for hopd.
//
// TODO(dadrian): Should this be in a non-main package?
type Flags struct {
	Host string
	Port string
}

func main() {
	logrus.SetLevel(logrus.InfoLevel)

	var fs flag.FlagSet
	f := Flags{}

	var sockAddr string
	fs.StringVar(&sockAddr, "s", app.DefaultHopAuthSocket, "indicates custom sockaddr to use for auth grant")

	fs.StringVar(&f.Port, "p", app.DefaultHopPort, "port to listen on")

	fs.StringVar(&f.Host, "h", "localhost", "hostname/ip addr to listen on")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		return
	}

	pktConn, err := net.ListenPacket("udp", net.JoinHostPort(f.Host, f.Port))
	if err != nil {
		logrus.Fatalf("unable to open socket for address %s:%s : %s", f.Host, f.Port, err)
	}
	udpConn := pktConn.(*net.UDPConn)

	// TODO(dadrian): Parse a config file
	tconf, _ := app.NewTestServerConfig(app.TestDataPathPrefixDef)

	underlying, err := transport.NewServer(udpConn, *tconf)
	if err != nil {
		logrus.Fatalf("unable to open transport server: %s", err)
	}

	serverConfig := &app.HopServerConfig{
		SockAddr:                 sockAddr,
		MaxOutstandingAuthgrants: 50,
	}
	s, err := app.NewHopServer(underlying, serverConfig)
	if err != nil {
		logrus.Fatal(err)
	}
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Interrupt, syscall.SIGTERM) // TODO(dadrian): Does this work on Windows?
	go func() {
		s.Serve() //starts transport layer server, authgrant server, and listens for hop conns
		sc <- syscall.SIGTERM
	}()
	<-sc
}
