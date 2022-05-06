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
