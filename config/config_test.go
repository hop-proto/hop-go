package config

import (
	"bytes"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp/cmpopts"
	"gotest.tools/assert"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

func generateCerts(t *testing.T) (root, intermediate, leaf *certs.Certificate, keyPair *keys.X25519KeyPair) {
	rootKey := keys.GenerateNewSigningKeyPair()
	rootID := &certs.Identity{
		PublicKey: rootKey.Public,
		Names:     []certs.Name{certs.DNSName("root.com")},
	}
	root, err := certs.SelfSignRoot(rootID, rootKey)
	assert.NilError(t, err)
	root.ProvideKey((*[32]byte)(&rootKey.Private))

	intermediateKey := keys.GenerateNewSigningKeyPair()
	intermediateID := &certs.Identity{
		PublicKey: intermediateKey.Public,
		Names:     []certs.Name{certs.DNSName("intermediate.com")},
	}
	intermediate, err = certs.IssueIntermediate(root, intermediateID)
	assert.NilError(t, err)
	intermediate.ProvideKey((*[32]byte)(&intermediateKey.Private))

	keyPair = keys.GenerateNewX25519KeyPair()
	identity := &certs.Identity{
		PublicKey: keyPair.Public,
		Names:     []certs.Name{certs.DNSName("leaf.com")},
	}
	leaf, err = certs.IssueLeaf(intermediate, identity)
	assert.NilError(t, err)

	return root, intermediate, leaf, keyPair
}

func TestLoadClientConfig(t *testing.T) {
	c, err := LoadClientConfigFromFile("testdata/client")
	assert.NilError(t, err)
	key := "/path/to/key.pem"
	cert := "/path/to/cert.pem"
	hostname := "example.localhost"
	autoSelfSign := false
	ServerKEMKey := "/path/to/serverKEMKey.pub"
	expected := &ClientConfig{
		Global: HostConfigOptional{
			CAFiles:     []string{"/path/to/ca.pem", "/path/to/other.pem"},
			Key:         &key,
			Certificate: &cert,
		},
		Hosts: []HostConfigOptional{{
			Patterns:     []string{"example.localhost"},
			AutoSelfSign: &autoSelfSign,
			Hostname:     &hostname,
			Port:         1234,
			ServerKEMKey: &ServerKEMKey,
		}},
	}
	assert.DeepEqual(t, c, expected)
}

const serverToml = `ListenAddress = ":77"

Key = "etc/hopd/id_hop.pem"
Certificate = "etc/hopd/id_hop.cert"
CAFiles = [ "etc/hopd/intermediate.cert" , "etc/hopd/root.cert"]

EnableAuthgrants = false
Users = ["user"]
HiddenModeVHostNames = ["example.com"]`

func TestLoadServerConfig(t *testing.T) {
	root, intermediate, leaf, keyPair := generateCerts(t)
	keyBytes := &bytes.Buffer{}
	err := keys.EncodeDHKeyToPEM(keyBytes, keyPair)
	assert.NilError(t, err)

	rootBytes, err := certs.EncodeCertificateToPEM(root)
	assert.NilError(t, err)
	intermediateBytes, err := certs.EncodeCertificateToPEM(intermediate)
	assert.NilError(t, err)
	leafBytes, err := certs.EncodeCertificateToPEM(leaf)
	assert.NilError(t, err)

	fileSystem = &fstest.MapFS{
		"etc/hopd/config.toml":       &fstest.MapFile{Data: []byte(serverToml)},
		"etc/hopd/id_hop.pem":        &fstest.MapFile{Data: keyBytes.Bytes()},
		"etc/hopd/id_hop.cert":       &fstest.MapFile{Data: leafBytes},
		"etc/hopd/intermediate.cert": &fstest.MapFile{Data: intermediateBytes},
		"etc/hopd/root.cert":         &fstest.MapFile{Data: rootBytes},
	}

	c, err := LoadServerConfigFromFile("etc/hopd/config.toml")
	assert.NilError(t, err)
	expected := &ServerConfig{
		ListenAddress:        ":77",
		Key:                  keyPair,
		Certificate:          leaf,
		CACerts:              []*certs.Certificate{root, leaf},
		EnableAuthgrants:     false,
		Users:                []string{"user"},
		HiddenModeVHostNames: []string{"example.com"},
		Names:                []NameConfig{},
		HandshakeTimeout:     15 * time.Second,
		DataTimeout:          0 * time.Second,
	}
	// TODO(hosono) there is currently no good way to compare certificates as equal
	assert.DeepEqual(t, c, expected, cmpopts.IgnoreFields(ServerConfig{}, "Certificate", "Intermediate", "CACerts"))
}
