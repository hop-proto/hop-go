package tokens

import (
	"io"
	"os"
	"testing"

	"gotest.tools/assert"
)

func TestTokenizer(t *testing.T) {
	f, _ := os.Open("testdata/client")
	b, _ := io.ReadAll(f)
	tokens, err := Tokenize(b)
	assert.NilError(t, err)
	t.Fail()
	t.Log(tokens)
}
