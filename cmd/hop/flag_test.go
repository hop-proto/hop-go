package main

import (
	"testing"

	"gotest.tools/assert"
)

func TestFlags(t *testing.T) {
	args := []string{"-L", "1000:localhost:2000", "-R", "3000:other:4000", "remotehost", "-K", "-R", "1111:127.0.0.1:2222", "-L", "3333:otherhost:4444"}
	config, err := configFromCmdLineFlags(args)
	assert.NilError(t, err)
	assert.Equal(t, config.Principal, true)
	assert.Equal(t, config.Hostname, "remotehost")
	assert.Equal(t, len(config.LocalArgs), 2)
	assert.Equal(t, config.LocalArgs[0], "1000:localhost:2000")
	assert.Equal(t, config.LocalArgs[1], "3333:otherhost:4444")
	assert.Equal(t, len(config.RemoteArgs), 2)
	assert.Equal(t, config.RemoteArgs[0], "3000:other:4000")
	assert.Equal(t, config.RemoteArgs[1], "1111:127.0.0.1:2222")
}
