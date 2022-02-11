// hop-keygen generates keys to be used with Hop.
//
// hop-keygen can generate private X25519 and Ed25519 keys for use with Hop.
// Clients will usually generate their own X25519 keys for key negotiation. This
// key is usually stored in ~/.hop/id_hop.pem. The public key will be in
// id_hop.pub.
//
// hop-keygen can optionally generate new signing (Ed25519) keys for use with
// Hop. This is only required if you are generating a signing certificate, and
// usually only required for server operator wishing to deploy a PKI rather than
// static keys.
package main

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/config"
	"zmap.io/portal/keys"
)

// Flags holds all the command-line flags for hop-keygen.
type Flags struct {
	Signing   bool
	Name      string
	Directory string
}

func main() {
	logrus.SetLevel(logrus.InfoLevel)

	f := Flags{}
	flag.BoolVar(&f.Signing, "signing", false, "Generate a signing key (Ed25519), rather than a handshake (X25519) key")
	flag.StringVar(&f.Name, "name", "id_hop", "Name of the key. By default, keys are named id_hop and stored ~/.hop. The private key will have the suffix .pem, and the public key will have the suffix .pub")
	flag.StringVar(&f.Directory, "directory", "", "Directory to store keys in. By default, this is ~/.hop")

	flag.Parse()

	if f.Name == "" {
		logrus.Fatalf("keys cannot have an empty name")
	}

	if f.Directory == "" {
		f.Directory = config.UserDirectory()
	}
	prefix := filepath.Join(f.Directory, f.Name)

	privateKeyPath := prefix + ".pem"
	fd, err := os.OpenFile(privateKeyPath, os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logrus.Fatalf("unable to open or create private key file %q: %s", privateKeyPath, err)
	}
	defer fd.Close() //nolint:staticcheck

	publicKeyPath := prefix + ".pub"
	pfd, err := os.Create(publicKeyPath)
	if err != nil {
		logrus.Fatalf("unable to create public key file %q: %s", publicKeyPath, err)
	}
	defer pfd.Close() // nolint:staticheck

	if f.Signing {
		kp := keys.GenerateNewSigningKeyPair()
		if err := keys.EncodeSigningKeyToPEM(fd, kp); err != nil {
			logrus.Fatalf("unable to write private key: %s", err)
		}
		pfd.WriteString(kp.Private.String())
	} else {
		kp := keys.GenerateNewX25519KeyPair()
		if err := keys.EncodeDHKeyToPEM(fd, kp); err != nil {
			logrus.Fatalf("unable to write private key: %s", err)
		}
		pfd.WriteString(kp.Public.String())
	}
	fd.Write([]byte{'\n'})
	pfd.Write([]byte{'\n'})
	logrus.Infof("wrote private key to %s", privateKeyPath)
	logrus.Infof("wrote public key to %s", publicKeyPath)
}
