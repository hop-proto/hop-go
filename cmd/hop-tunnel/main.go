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

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/transport"
)

const forever = time.Duration(math.MaxInt64)

var leafPath, intermediatePath, rootsPath string
var keyPath string

func openCerts() (leaf, intermediate *certs.Certificate, keyPair *keys.X25519KeyPair) {
	var err error
	logrus.Infof("using key %q", keyPath)
	keyPair, err = keys.ReadDHKeyFromPEMFile(keyPath)
	if err != nil {
		logrus.Fatalf("unable to open key pair %q: %s", keyPath, err)
	}
	logrus.Infof("using leaf %q", leafPath)
	leaf, err = certs.ReadCertificatePEMFile(leafPath)
	if err != nil {
		logrus.Fatalf("unable to open leaf %q: %s", leafPath, err)
	}
	logrus.Infof("using intermediate %q", intermediatePath)
	intermediate, err = certs.ReadCertificatePEMFile(intermediatePath)
	if err != nil {
		logrus.Fatalf("unable to open intermediate %q: %s", intermediatePath, err)
	}
	return
}

func issueCerts() (leaf, intermediate *certs.Certificate, keyPair *keys.X25519KeyPair) {
	rootKeyPair := keys.GenerateNewSigningKeyPair()
	rootIdentity := certs.Identity{
		Names:     []certs.Name{},
		PublicKey: rootKeyPair.Public,
	}
	root, err := certs.SelfSignRoot(&rootIdentity, rootKeyPair)
	if err != nil {
		logrus.Fatalf("error issuing root: %s", err)
	}
	root.ProvideKey((*[32]byte)(&rootKeyPair.Private))

	intermediateKeyPair := keys.GenerateNewSigningKeyPair()
	intermediateIdentity := certs.Identity{
		Names:     []certs.Name{},
		PublicKey: intermediateKeyPair.Public,
	}
	intermediate, err = certs.IssueIntermediate(root, &intermediateIdentity)
	if err != nil {
		logrus.Fatalf("error issuing intermediate: %s", err)
	}
	intermediate.ProvideKey((*[32]byte)(&intermediateKeyPair.Private))
	keyPair = keys.GenerateNewX25519KeyPair()
	identity := certs.Identity{
		Names:     []certs.Name{certs.DNSName("hop.local")},
		PublicKey: keyPair.Public,
	}
	leaf, err = certs.IssueLeaf(intermediate, &identity)
	if err != nil {
		logrus.Fatalf("unable to issue leaf certificate: %s", err)
	}
	return leaf, intermediate, keyPair
}

func main() {
	flag.StringVar(&leafPath, "leaf", "", "path to leaf certificate pem")
	flag.StringVar(&intermediatePath, "intermediate", "", "path to intermediate certificate pem")
	flag.StringVar(&rootsPath, "roots", "", "path to root store pem")
	flag.StringVar(&keyPath, "key", "", "path to key for leaf certificate")
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
		config := transport.ClientConfig{}
		if rootsPath != "" {
			store, err := certs.LoadRootStoreFromPEMFile(rootsPath)
			if err != nil {
				logrus.Fatalf("unable to open root store: %s", err)
			}
			config.Verify = transport.VerifyConfig{
				Store: *store,
			}
		}
		c, err := transport.Dial("udp", address, config)
		if err != nil {
			logrus.Fatalf("client dial failed: %s", err)
		}
		go io.Copy(c, os.Stdin)
		go io.Copy(os.Stdout, c)
	case "listen":
		var leaf, intermediate *certs.Certificate
		var keyPair *keys.X25519KeyPair
		if leafPath != "" || intermediatePath != "" {
			leaf, intermediate, keyPair = openCerts()
		} else {
			leaf, intermediate, keyPair = issueCerts()
		}

		config := transport.ServerConfig{}
		config.StartingReadTimeout = forever
		config.KeyPair = keyPair
		config.Certificate = leaf
		config.Intermediate = intermediate

		pktConn, err := net.ListenPacket("udp", address)
		if err != nil {
			logrus.Fatalf("unable to listen on %q: %s", address, err)
		}
		logrus.Infof("listening on %s", pktConn.LocalAddr().String())
		udpConn := pktConn.(*net.UDPConn)
		s, err := transport.NewServer(udpConn, config)
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
