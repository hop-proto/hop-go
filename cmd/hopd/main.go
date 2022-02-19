package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/app"
	"zmap.io/portal/config"
	"zmap.io/portal/keys"
	"zmap.io/portal/pkg/combinators"
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
	keyPath := combinators.StringOr(sc.Key, config.DefaultServerKeyPath())

	keyPair, err := keys.ReadDHKeyFromPEMFile(keyPath)
	if err != nil {
		logrus.Fatalf("unable to read key %q: %s", keyPath, err)
	}

	// certificate, err := certs.ReadCertificatePEMFile(f.Certificate)
	// if err != nil {
	// 	logrus.Fatalf("unable to read certificate from file %q: %s", f.Certificate, err)
	// }

	pktConn, err := net.ListenPacket("udp", sc.ListenAddress)
	if err != nil {
		logrus.Fatalf("unable to open socket for address %s: %s", sc.ListenAddress, err)
	}
	udpConn := pktConn.(*net.UDPConn)
	logrus.Infof("listening at %s", udpConn.LocalAddr())

	// TODO(dadrian): Parse a config file
	tconf := transport.ServerConfig{
		KeyPair:     keyPair,
		Certificate: nil, // TODO(dadrian): Read certs from config
		ClientVerify: &transport.VerifyConfig{
			InsecureSkipVerify: true, // Do authorized keys instead
		},
		AutoSelfSign: true,
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
