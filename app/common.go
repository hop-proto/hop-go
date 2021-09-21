package app

import (
	"encoding/hex"
	"errors"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/certs"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

const (
	defaultHopPort       = "7777"
	defaultKeyPath       = "/.hop/key"
	clientUsage          = "hop [user@]host[:port] [-K or -k path] [-c cmd] [-q] [-h]"
	testDataPathPrefix   = "/home/baumanl/.hop/"
	defaultHopAuthSocket = "@hopauth"
)

//ErrClientInvalidUsage returned by client when unable to parse command line arguments
var ErrClientInvalidUsage = errors.New("usage: " + clientUsage)

//ErrClientLoadingKeys returned by client (principal) when unable to load keys from specified location
var ErrClientLoadingKeys = errors.New("unable to load keys")

//ErrClientGettingAuthorization  is returned by client when it can't get
var ErrClientGettingAuthorization = errors.New("failed to get authorization")

//ErrClientStartingUnderlying is returned by client when it can't start transport layer conn
var ErrClientStartingUnderlying = errors.New("error starting underlying conn")

//ErrClientUnauthorized is returned by client when it is not authorized to perform the action it requested
var ErrClientUnauthorized = errors.New("client not authorized")

//ErrClientStartingExecTube is returned by client when cmd execution and/or I/O redirection fails
var ErrClientStartingExecTube = errors.New("failed to start session")

func newTestServerConfig() (*transport.ServerConfig, *transport.VerifyConfig) {
	keyPair, err := keys.ReadDHKeyFromPEMFile(testDataPathPrefix + "testdata/leaf-key.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH KEYPAIR %v", err)
	}
	certificate, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/leaf.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH CERTS %v", err)
	}
	intermediate, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/intermediate.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH INT CERTS %v", err)
	}
	root, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/root.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH ROOT CERT %v", err)
	}
	if hex.EncodeToString(root.Fingerprint[:]) != "087aa52c8c287f34fcf6b33b22d68b02489d7168edae696a8ce4ae5e825bd1e9" {
		logrus.Fatal("S: ROOT FINGERPRINT DOES NOT MATCH")
	}
	server := transport.ServerConfig{
		KeyPair:      keyPair,
		Certificate:  certificate,
		Intermediate: intermediate,
	}
	verify := transport.VerifyConfig{
		Store: certs.Store{},
	}
	verify.Store.AddCertificate(root)
	return &server, &verify
}
