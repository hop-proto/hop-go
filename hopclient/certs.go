package hopclient

import (
	"github.com/sirupsen/logrus"
	"hop.computer/hop/certs"
	"hop.computer/hop/config"
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
