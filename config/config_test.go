package config

import (
	"testing"

	"gotest.tools/assert"
)

func TestLoadClientConfig(t *testing.T) {
	c, err := LoadClientConfigFromFile("testdata/client")
	assert.NilError(t, err)
	expected := &ClientConfig{
		Global: HostConfig{
			CAFiles: []string{"/path/to/ca.pem", "/path/to/other.pem"},
		},
		Hosts: []HostConfig{{
			Patterns:     []string{"example.localhost"},
			Key:          "/path/to/key.pem",
			Certificate:  "/path/to/cert.pem",
			AutoSelfSign: False,
			Hostname:     "example.localhost",
			Port:         1234,
		}},
	}
	assert.DeepEqual(t, c, expected)
}

func TestLoadServerConfig(t *testing.T) {
	c, err := LoadServerConfigFromFile("testdata/server")
	assert.NilError(t, err)
	expected := &ServerConfig{
		ListenAddress: ":77",
		Key:           "/etc/hopd/id_hop.pem",
		Certificate:   "/etc/hopd/id_hop.cert",
	}
	assert.DeepEqual(t, c, expected)
}
