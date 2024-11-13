package core

import (
	"gotest.tools/assert"
	"hop.computer/hop/common"
	"path/filepath"
	"testing"
)

func TestReading(t *testing.T) {
	authKeysPath := filepath.Join("./", common.KnownHostsFile)
	authKeys, err := ParseKnownHostFile(authKeysPath)
	assert.NilError(t, err)
	assert.Assert(t, authKeys != nil)
}
