package hopclient

import (
	"os"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/certs"
	"hop.computer/hop/config"
	"hop.computer/hop/keys"
	"hop.computer/hop/transport"
)

// client expects server to return certificate with a specific
// certs.Name
func constructVerifyConfig(hc *config.HostConfig) transport.VerifyConfig {
	verifyConfig := transport.VerifyConfig{
		Store: certs.Store{},
	}
	if hc.ServerName != "" {
		verifyConfig.Name = certs.DNSName(hc.ServerName)
	} else if hc.ServerIPv4 != "" {
		verifyConfig.Name = certs.Name{
			Type:  certs.TypeIPv4Address,
			Label: []byte(hc.ServerIPv4),
		}
	} else if hc.ServerIPv6 != "" {
		verifyConfig.Name = certs.Name{
			Type:  certs.TypeIPv6Address,
			Label: []byte(hc.ServerIPv6),
		}
	} else {
		verifyConfig.Name = certs.DNSName(hc.Hostname)
	}
	return verifyConfig
}

// client will use these certs to verify server leaf certificates
func (c *HopClient) loadCAFiles(store *certs.Store) {
	for _, file := range c.hostconfig.CAFiles {
		cert, err := certs.ReadCertificatePEMFileFS(file, c.Fsystem)
		if err != nil {
			logrus.Fatalf("client: error loading cert at %s: %s", file, err)
			continue
		}
		store.AddCertificate(cert)
		logrus.Debugf("client: loaded cert with fingerprint: %x", cert.Fingerprint)
	}
}

// TODO (paul) check if this is the right place to put this function or in another file
func loadServerPublicKey(serverPublicKeyPath string) (*keys.PublicKey, error) {

	pubKeyBytes, err := os.ReadFile(serverPublicKeyPath)
	if err != nil {
		logrus.Errorf("could not read public key file: %s", err)
		return nil, err
	}
	pubKey, err := keys.ParseDHPublicKey(string(pubKeyBytes))
	if err != nil {
		logrus.Errorf("client: unable to parse the server public key file: %s", err)
		return nil, err
	}
	logrus.Debugf("client: paul finish: %x", pubKey)
	return pubKey, nil
}
