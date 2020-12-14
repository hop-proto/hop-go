package portal

import (
	"testing"

	"gotest.tools/assert"
)

func TestListener(t *testing.T) {
	listener, err := Listen("udp", "127.0.0.1:0", &Config{})
	assert.NilError(t, err)
	err = listener.Close()
	assert.NilError(t, err)
	conn, err := listener.Accept()
	assert.Check(t, conn == nil)
	assert.Check(t, err != nil)
}
