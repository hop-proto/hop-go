package main

import (
	"flag"
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/keys"
)

var signing bool

var output = os.Stdout

func main() {
	logrus.SetLevel(logrus.InfoLevel)

	flag.BoolVar(&signing, "signing", false, "Key type used for intermediate and root certificates (Ed25519). Default is X25519.")
	flag.Parse()
	if signing {
		keyPair := keys.GenerateNewSigningKeyPair()
		output.Write([]byte(keyPair.Public.String()))
	} else {
		keyPair := keys.GenerateNewX25519KeyPair()
		output.Write([]byte(keyPair.Public.String()))
	}
	output.Write([]byte("\n"))
	output.Close()
}
