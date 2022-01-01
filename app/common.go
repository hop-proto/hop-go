package app

import (
	"errors"
	"io/fs"
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/certs"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

//Defaults and constants for starting a hop session
const (
	DefaultHopPort        = "7777"
	DefaultKeyPath        = "/.hop/key"
	clientUsage           = "hop [user@]host[:port] [-K or -k path] [-L port:host:hostport] [-R port:host:hostport] [-N] [-c cmd] [-q] [-h]"
	TestDataPathPrefixDef = "../../certs/"
	DefaultHopAuthSocket  = "@hopauth"
)

//Tube Type constants
const (
	ExecTube      = byte(1)
	AuthGrantTube = byte(2)
	NetProxyTube  = byte(3) //Net Proxy should maybe be unreliable tube?
	UserAuthTube  = byte(4)
	LocalPFTube   = byte(5)
	RemotePFTube  = byte(6)
)

var hostToIPAddr = map[string]string{ //TODO(baumanl): this should be dealt with in some user hop config file
	"scratch-01": "10.216.2.64",
	"scratch-02": "10.216.2.128",
	"scratch-07": "10.216.2.208",
	"localhost":  "127.0.0.1",
}

//ErrInvalidPortForwardingArgs returned when client receives unsupported -L or -R options
var ErrInvalidPortForwardingArgs = errors.New("port forwarding currently only supported with port:host:hostport format")

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

//NewTestServerConfig populates server config and verify config with sample cert data
func NewTestServerConfig(testDataPathPrefix string) (*transport.ServerConfig, *transport.VerifyConfig) {
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
	err = certs.VerifyParent(certificate, intermediate)
	if err != nil {
		logrus.Fatal("Verify Parent Issue: ", err)
	}
	err = certs.VerifyParent(intermediate, root)
	if err != nil {
		logrus.Fatal("Verify Parent Issue: ", err)
	}
	err = certs.VerifyParent(root, root)
	if err != nil {
		logrus.Fatal("Verify Parent Issue: ", err)
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

//KeyGen generates a new key pair and adds it to local authorized keys file
func KeyGen(dir string, filename string, addToAuthKeys bool) (*keys.X25519KeyPair, error) {
	suffix := dir + "/" + filename
	pair := keys.GenerateNewX25519KeyPair()
	path, _ := os.UserHomeDir()
	path += dir
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.Mkdir(path, fs.ModeDir|0700)
		if err != nil {
			logrus.Error(err)
			return nil, err
		}
	}
	path += "/" + filename
	f, e := os.Create(path)
	if e != nil {
		logrus.Errorf("error opening default key file: %v", e)
		return nil, e
	}
	logrus.Infof("adding private to ~%v: %v", suffix, pair.Private.String())
	f.WriteString(pair.Private.String())
	f.Close()

	path, _ = os.UserHomeDir()
	path += suffix + ".pub"
	f, e = os.Create(path)
	if e != nil {
		logrus.Errorf("error opening default key file: %v", e)
		return nil, e
	}
	logrus.Infof("adding public to ~%v.pub: %v", suffix, pair.Public.String())
	f.WriteString(pair.Public.String())
	f.Close()
	if addToAuthKeys {
		logrus.Info("adding to authorized keys")
		path, _ = os.UserHomeDir()
		path += "/.hop/authorized_keys" //adds the key to its own authorized key file so that localhost operations will work
		_, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			logrus.Info("file does not exist, creating...")
			f, e := os.Create(path)
			if e != nil {
				logrus.Error(e)
				return nil, e
			}
			f.Close()
		}
		auth, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
		if e != nil {
			logrus.Errorf("error opening auth key file: %v", e)
			return nil, e
		}
		defer auth.Close()
		logrus.Infof("adding public to auth keys: %v", pair.Public.String())
		auth.WriteString(pair.Public.String())
		auth.WriteString("\n")
	}
	return pair, nil
}
