package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"

	"hop.computer/hop/acme"
	"hop.computer/hop/certs"
	"hop.computer/hop/flags"
	"hop.computer/hop/keys"
)

func checkErr(err error) {
	if err != nil {
		logrus.Fatal(err)
	}
}

// TODO(hosono) make these configurable
var signingCertPath = "/etc/hop/signing.cert"
var signingKeyPath = "/etc/hop/signing.pem"

func main() {
	f, err := flags.ParseServerArgs(os.Args)
	if err != nil {
		logrus.Error(err)
		return
	}

	if f.Verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	sc, err := flags.LoadServerConfigFromFlags(f)
	if err != nil {
		if perr, ok := err.(toml.ParseError); ok {
			logrus.Fatal(perr.ErrorWithUsage())
		} else {
			logrus.Fatalf("error loading config: %s", err)
		}
	}
	sc.HandshakeTimeout = 15 * time.Second

	signingCert, _, err := certs.ReadCertificateBytesFromPEMFile(signingCertPath)
	checkErr(err)
	signingKey, err := keys.ReadSigningPrivateKeyPEMFile(signingKeyPath)
	checkErr(err)
	signingCert.ProvideKey((*[32]byte)(&signingKey.Private))

	serverConfig := &acme.AcmeServerConfig{
		ServerConfig:       sc,
		SigningCertificate: signingCert,
		Log:                logrus.WithField("acmeServer", ""),
	}
	server, err := acme.NewAcmeServer(serverConfig)
	checkErr(err)

	sch := make(chan os.Signal, 1)
	signal.Notify(sch, os.Interrupt, syscall.SIGTERM)
	go func() {
		server.Serve()
		sch <- syscall.SIGTERM
	}()
	<-sch

}
