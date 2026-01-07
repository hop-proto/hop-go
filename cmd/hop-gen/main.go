package main

import (
	"crypto/rand"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/keys"
)

var signing bool
var privateKeyPath string
var kem bool

var output = os.Stdout

func main() {
	logrus.SetLevel(logrus.InfoLevel)

	flag.BoolVar(&signing, "signing", false, "Key type used for intermediate and root certificates (Ed25519). Default is X25519.")
	flag.StringVar(&privateKeyPath, "private", "", "path to private key (will output public key)")
	flag.BoolVar(&kem, "kem", false, "Generate a ML-KEM key (ML-KEM 512), rather than a handshake (X25519) key")
	flag.Parse()

	defer output.Close()
	defer output.Write([]byte("\n"))

	// Conversion
	if privateKeyPath != "" {
		b, err := ioutil.ReadFile(privateKeyPath)
		if err != nil {
			logrus.Fatalf("unable to open private key file: %s", err)
		}
		p, _ := pem.Decode(b)
		if signing {
			keyPair, err := keys.SigningKeyFromPEM(p)
			if err != nil {
				logrus.Fatalf("unable to parse private key: %s", err)
			}
			os.Stdout.Write([]byte(keyPair.Public.String()))
		} else if kem {
			keyPair, err := keys.KEMKeyFromPEM(p)
			if err != nil {
				logrus.Fatalf("unable to parse kem private key: %s", err)
			}
			os.Stdout.Write([]byte(keys.KEMPublicKeyToString(&keyPair.Public)))
		} else {
			keyPair, err := keys.DHKeyFromPEM(p)
			if err != nil {
				logrus.Fatalf("unable to parse private key: %s", err)
			}
			os.Stdout.Write([]byte(keyPair.Public.String()))
		}
		return
	}

	// Generation
	if signing {
		keyPair := keys.GenerateNewSigningKeyPair()
		output.Write([]byte(keyPair.Private.String()))
	} else if kem {
		keyPair, err := keys.GenerateKEMKeyPair(rand.Reader)
		if err != nil {
			logrus.Fatalf("unable to genrate ml-kem keypair: %s", err)
		}
		output.Write([]byte(keyPair.Seed.String()))

	} else {
		keyPair := keys.GenerateNewX25519KeyPair()
		output.Write([]byte(keyPair.Private.String()))
	}
}
