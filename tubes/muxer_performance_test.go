package tubes

import (
	"crypto/rand"
	"testing"

	"gotest.tools/assert"
)

const benchMsgSize = 1

func benchTubeWrite(b *testing.B, reader, writer *Unreliable, size int) {
	go func() {
		buf := make([]byte, size)
		for {
			reader.ReadMsg(buf)
		}
	}()

	msg := make([]byte, size)
	n, err := rand.Read(msg)
	assert.NilError(b, err)
	assert.Equal(b, len(msg), n)
	for i := 0; i < b.N; i++ {
		writer.WriteMsg(msg)
	}
}

func BenchmarkMuxer(b *testing.B) {
	server, client := newMuxersForTest(b)

	clientTube, err := client.CreateUnreliableTube(TubeType(1))
	assert.NilError(b, err)

	serverTube, err := server.Accept()
	assert.NilError(b, err)

	benchTubeWrite(b, serverTube.(*Unreliable), clientTube, benchMsgSize)
}
