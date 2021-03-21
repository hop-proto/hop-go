package main

import (
	"encoding/pem"
	"flag"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/certs"
	"zmap.io/portal/keys"
)

var certTypeStr string
var keyFilePath string
var dnsName string

var output = os.Stdout

func main() {
	logrus.SetLevel(logrus.InfoLevel)

	flag.StringVar(&keyFilePath, "key-file", "key.pem", "private key file")
	flag.StringVar(&dnsName, "dns-name", "", "dns name for the cert")
	flag.StringVar(&certTypeStr, "type", "leaf", "type of certificate to issue (leaf|intermediate|root)")
	flag.Parse()

	certType, err := certs.CertificateTypeFromString(certTypeStr)

	if err != nil {
		logrus.Fatalf("%s", err)
	}
	switch certType {
	case certs.Root:
		data, err := ioutil.ReadFile(keyFilePath)
		if err != nil {
			logrus.Fatalf("unable to open key file: %s", err)
		}
		p, _ := pem.Decode(data)
		keyPair, err := keys.SigningKeyFromPEM(p)
		if err != nil {
			logrus.Fatalf("unable to parse private key: %s", err)
		}
		identity := certs.Identity{
			PublicKey: keyPair.Public,
			Names: []certs.Name{
				{
					Type:  certs.DNSName,
					Label: dnsName,
				},
			},
		}
		root, err := certs.SelfSignRoot(&identity, keyPair)
		if err != nil {
			logrus.Fatalf("unable to self-sign root: %s", err)
		}
		pemBytes, err := certs.EncodeCertificateToPEM(root)
		if err != nil {
			logrus.Fatalf("unable to encode certificate to PEM: %s", err)
		}
		output.Write(pemBytes)
	default:
		panic("unimplemented")
	}
	output.Close()
}
