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
var parentFilePath string
var publicKeyFilePath string

var dnsName string

var output = os.Stdout

func main() {
	logrus.SetLevel(logrus.InfoLevel)

	flag.StringVar(&keyFilePath, "key-file", "key.pem", "private key file")
	flag.StringVar(&parentFilePath, "cert-file", "cert.pem", "pem file of parent certificate")
	flag.StringVar(&dnsName, "dns-name", "", "dns name for the cert")
	flag.StringVar(&certTypeStr, "type", "leaf", "type of certificate to issue (leaf|intermediate|root)")
	flag.StringVar(&publicKeyFilePath, "public-key", "pub.pem", "public key file")
	flag.Parse()

	certType, err := certs.CertificateTypeFromString(certTypeStr)

	if err != nil {
		logrus.Fatalf("%s", err)
	}

	data, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		logrus.Fatalf("unable to open key file: %s", err)
	}
	p, _ := pem.Decode(data)
	if p == nil {
		logrus.Fatalf("unable to parse PEM file %s", keyFilePath)
	}
	signingKeyPair, err := keys.SigningKeyFromPEM(p)
	if err != nil {
		logrus.Fatalf("unable to parse private key: %s", err)
	}

	switch certType {
	case certs.Intermediate:
		data, err = ioutil.ReadFile(parentFilePath)
		if err != nil {
			logrus.Fatalf("could not open parent cert file: %s", err)
		}
		parent, err := certs.ReadCertificatePEM(data)
		if err != nil {
			logrus.Fatalf("could not deserialize parent cert: %s", err)
		}
		err = parent.ProvideKey((*[32]byte)(&signingKeyPair.Private))
		if err != nil {
			logrus.Fatalf("bad private key: %s", err)
		}
		pubKeyBytes, err := ioutil.ReadFile(publicKeyFilePath)
		if err != nil {
			logrus.Fatalf("could not read public key file: %s", err)
		}
		pubKey, err := keys.ParseSigningPublicKey(string(pubKeyBytes))
		if err != nil {
			logrus.Fatalf("unable to parse signing public key: %s")
		}
		identity := certs.Identity{
			PublicKey: *pubKey,
			Names: []certs.Name{
				{
					Type:  certs.DNSName,
					Label: dnsName,
				},
			},
		}
		intermediate, err := certs.IssueIntermediate(parent, &identity)
		if err != nil {
			logrus.Fatalf("unable to issue intermediate: %s", err)
		}
		pemBytes, err := certs.EncodeCertificateToPEM(intermediate)
		if err != nil {
			logrus.Fatalf("unable to encode certificate to PEM: %s", err)
		}
		output.Write(pemBytes)
	case certs.Root:
		identity := certs.Identity{
			PublicKey: signingKeyPair.Public,
			Names: []certs.Name{
				{
					Type:  certs.DNSName,
					Label: dnsName,
				},
			},
		}
		root, err := certs.SelfSignRoot(&identity, signingKeyPair)
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
