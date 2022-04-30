package config

import (
	"testing"

	"gotest.tools/assert"
)

func TestLoadClientConfig(t *testing.T) {
	c, err := LoadClientConfigFromFile("ast/testdata/client")
	assert.NilError(t, err)
	t.Log(*c)
	// TODO(dadrian): Actually check the output
}

func TestLoadServerConfig(t *testing.T) {
	c, err := LoadServerConfigFromFile("ast/testdata/server")
	assert.NilError(t, err)
	t.Log(*c)
	// TODO(dadrian): Actually check the output
}

func TestConfigCopy(t *testing.T) {
	err := InitClient("ast/testdata/client")
	assert.NilError(t, err)
	cc := GetClient()
	copy := GetClientCopy("example.localhost")
	assert.Equal(t, cc.MatchHost("example.localhost").Hostname, copy.Hosts[0].Hostname)
}
