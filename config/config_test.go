package config

import (
	"testing"

	"gotest.tools/assert"
)

func TestLoadClientConfig(t *testing.T) {
	c, err := LoadClientConfigFromFile("testdata/client")
	assert.NilError(t, err)
	key := "/path/to/key.pem"
	cert := "/path/to/cert.pem"
	hostname := "example.localhost"
	autoSelfSign := false
	ServerKEMKey := "/path/to/serverKey.pub"
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

func TestLoadServerConfig(t *testing.T) {
	c, err := LoadServerConfigFromFile("testdata/server")
	assert.NilError(t, err)
	ag := false
	expected := &ServerConfig{
		ListenAddress:        ":77",
		Key:                  "/etc/hopd/id_hop.pem",
		Certificate:          "/etc/hopd/id_hop.cert",
		CAFiles:              []string{"/etc/hopd/intermediate.cert", "/etc/hopd/root.cert"},
		EnableAuthgrants:     &ag,
		Users:                []string{"user"},
		HiddenModeVHostNames: []string{"example.com"},
	}
	assert.DeepEqual(t, c, expected)
}
