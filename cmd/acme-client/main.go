package main

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"

	"hop.computer/hop/acme"
	"hop.computer/hop/certs"
	"hop.computer/hop/flags"
	"hop.computer/hop/keys"
	// "hop.computer/hop/transport"
)

func checkErr(err error) {
	if err != nil {
		logrus.Fatalf("%v", err)
	}
}

func main() {
	f, err := flags.ParseClientArgs(os.Args)
	checkErr(err)
	if f.Verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// hc will be result of merging config file settings and flags
	hc, err := flags.LoadClientConfigFromFlags(f)
	if err != nil {
		if perr, ok := err.(toml.ParseError); ok {
			logrus.Fatal(perr.ErrorWithUsage())
		} else {
			logrus.Fatal(err)
		}
	}

	keyPair := keys.GenerateNewX25519KeyPair()
	config := &acme.AcmeClientConfig{
		HostConfig: hc,
		Key:        keyPair,
		// TODO(hosono) this is a bit of a hack. Acme client should have its own flags
		DomainName:    f.Cmd,
		ChallengePort: 8888,
	}

	client, err := acme.NewAcmeClient(config)
	checkErr(err)

	err = client.Dial()
	checkErr(err)

	cert, err := client.Run()
	checkErr(err)

	b, err := certs.EncodeCertificateToPEM(cert)
	checkErr(err)

	// Write cert and private key to std out
	fmt.Println(string(b))
	fmt.Println(keyPair.Private.String())
}
