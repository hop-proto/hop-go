package main

import (
	"flag"
	"io"
	"math"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/certs"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

const forever = time.Duration(math.MaxInt64)

func main() {
	flag.Parse()
	action := flag.Arg(0)
	address := flag.Arg(1)
	host, port, err := net.SplitHostPort(address)
	logrus.SetLevel(logrus.DebugLevel)
	if err != nil {
		logrus.Fatalf("unable to parse address %q: %s", address, err)
	}
	logrus.Infof("using host: %q:, port: %s", host, port)

	switch action {
	case "connect":
		config := transport.ClientConfig{
			Verify: transport.VerifyConfig{
				InsecureSkipVerify: true,
			},
		}
		c, err := transport.Dial("udp", address, config)
		if err != nil {
			logrus.Fatalf("client dial failed: %s", err)
		}
		go io.Copy(c, os.Stdin)
		go io.Copy(os.Stdout, c)
	case "listen":
		config := transport.ServerConfig{}
		config.StartingReadTimeout = forever
		config.KeyPair = keys.GenerateNewX25519KeyPair()
		identity := certs.Identity{
			Names:     []certs.Name{},
			PublicKey: config.KeyPair.Public,
		}
		config.Certificate, err = certs.SelfSignLeaf(&identity, config.KeyPair)
		if err != nil {
			logrus.Fatalf("unable to issue self-signed certificate: %s", err)
		}
		config.Intermediate = nil
		pktConn, err := net.ListenPacket("udp", address)
		if err != nil {
			logrus.Fatalf("unable to listen on %q: %s", address, err)
		}
		logrus.Infof("listening on %s", pktConn.LocalAddr().String())
		udpConn := pktConn.(*net.UDPConn)
		s, err := transport.NewServer(udpConn, &config)
		go s.Serve()
		if err != nil {
			logrus.Fatalf("unable to launch server: %s", err)
		}
		c, err := s.AcceptTimeout(forever)
		if err != nil {
			logrus.Fatalf("unable to accept connection: %s", err)
		}
		go io.Copy(c, os.Stdin)
		go io.Copy(os.Stdout, c)
	default:
		logrus.Fatalf("unknown action: %q", action)
	}
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGTERM, syscall.SIGINT)
	<-done
	logrus.Info("done")
}
