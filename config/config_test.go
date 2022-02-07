package config

import (
	"testing"

	"gotest.tools/assert"
)

func TestLoadConfig(t *testing.T) {
	c, err := LoadConfigFromFile("ast/testdata/client")
	assert.NilError(t, err)
	t.Log(*c)
	// TODO(dadrian): Actually check the output
}
