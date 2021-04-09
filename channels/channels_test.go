package channels

import (
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

func TestReadBuffering(t *testing.T) {

	server := Reliable{}
	client := Reliable{}

	written := make([]byte, 256)
	for i := range written {
		written[i] = byte(i)
	}
	n, err := server.Write(written)
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(len(written), n))

	read := 0
	for read < len(written) {
		smallBuffer := make([]byte, 10)
		client.Read(smallBuffer)
		// Assert the bytes are what we expect
		// TODO
	}
	//
}
