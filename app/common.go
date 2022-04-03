// Package app should be deleted
package app

// //Defaults and constants for starting a hop session
// const (
// 	DefaultHopPort        = "7777"
// 	DefaultKeyPath        = "/.hop/key"
// 	clientUsage           = "hop [user@]host[:port] [-K or -k path] [-L port:host:hostport] [-R port:host:hostport] [-N] [-c cmd] [-q] [-h]"
// 	TestDataPathPrefixDef = "../../certs/"

// )

// var HostToIPAddr = map[string]string{ //TODO(baumanl): this should be dealt with in some user hop config file
// 	"scratch-01": "10.216.2.64",
// 	"scratch-02": "10.216.2.128",
// 	"scratch-07": "10.216.2.208",
// 	"localhost":  "127.0.0.1",
// }

// //ErrClientInvalidUsage returned by client when unable to parse command line arguments
// var ErrClientInvalidUsage = errors.New("usage: " + clientUsage)

// //ErrClientLoadingKeys returned by client (principal) when unable to load keys from specified location
// var ErrClientLoadingKeys = errors.New("unable to load keys")

// //ErrClientGettingAuthorization  is returned by client when it can't get
// var ErrClientGettingAuthorization = errors.New("failed to get authorization")

// //ErrClientStartingUnderlying is returned by client when it can't start transport layer conn
// var ErrClientStartingUnderlying = errors.New("error starting underlying conn")

// //ErrClientUnauthorized is returned by client when it is not authorized to perform the action it requested
// var ErrClientUnauthorized = errors.New("client not authorized")

// //ErrClientStartingExecTube is returned by client when cmd execution and/or I/O redirection fails
// var ErrClientStartingExecTube = errors.New("failed to start session")

// //NewTestServerConfig populates server config and verify config with sample cert data
// func NewTestServerConfig(testDataPathPrefix string) (*transport.ServerConfig, *transport.VerifyConfig) {
// 	keyPair, err := keys.ReadDHKeyFromPEMFile(testDataPathPrefix + "testdata/leaf-key.pem")
// 	if err != nil {
// 		logrus.Fatalf("S: ERROR WITH KEYPAIR %v", err)
// 	}
// 	certificate, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/leaf.pem")
// 	if err != nil {
// 		logrus.Fatalf("S: ERROR WITH CERTS %v", err)
// 	}
// 	intermediate, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/intermediate.pem")
// 	if err != nil {
// 		logrus.Fatalf("S: ERROR WITH INT CERTS %v", err)
// 	}
// 	root, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/root.pem")
// 	if err != nil {
// 		logrus.Fatalf("S: ERROR WITH ROOT CERT %v", err)
// 	}
// 	err = certs.VerifyParent(certificate, intermediate)
// 	if err != nil {
// 		logrus.Fatal("Verify Parent Issue: ", err)
// 	}
// 	err = certs.VerifyParent(intermediate, root)
// 	if err != nil {
// 		logrus.Fatal("Verify Parent Issue: ", err)
// 	}
// 	err = certs.VerifyParent(root, root)
// 	if err != nil {
// 		logrus.Fatal("Verify Parent Issue: ", err)
// 	}

// 	server := transport.ServerConfig{
// 		KeyPair:      keyPair,
// 		Certificate:  certificate,
// 		Intermediate: intermediate,
// 	}
// 	verify := transport.VerifyConfig{
// 		Store: certs.Store{},
// 	}
// 	verify.Store.AddCertificate(root)
// 	return &server, &verify
// }
