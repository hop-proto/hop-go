package acme

import (
	"testing"

	"gotest.tools/assert"

	"hop.computer/hop/config"
)

func TestAcmeConfig(t *testing.T) {
	config := &AcmeServerConfig{
		ServerConfig: &config.ServerConfig{},
	}
	s, err := NewAcmeServer(config)
	assert.NilError(t, err)

	s.Serve()
}
