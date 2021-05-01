package snp

import (
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

var zero [25]uint64
var one [25]uint64 = [25]uint64{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

func newDefaultState() [25]uint64 {
	var out [25]uint64
	for i := range out {
		out[i] = uint64(i)
	}
	return out
}

func TestExtractAndAdd(t *testing.T) {

	t.Run("no offset, full", func(t *testing.T) {
		state := newDefaultState()
		in := one
		expected := state
		StateAddState(&expected, &in)
		assert.Assert(t, expected != zero)

		out := make([]byte, 200)
		StateExtractAndAddStateToBytes(&state, &in, 0, out)

		extracted := make([]byte, 200)
		StateExtractBytes(&expected, extracted)
		assert.Check(t, cmp.DeepEqual(extracted, out))
	})

	t.Run("no offset, partials", func(t *testing.T) {
		state := newDefaultState()
		in := one
		expected := state
		StateAddState(&expected, &in)
		assert.Assert(t, expected != zero)

		extracted := make([]byte, 200)
		StateExtractBytes(&expected, extracted)

		for i := 0; i < 200; i++ {
			out := make([]byte, i)
			StateExtractAndAddStateToBytes(&state, &in, 0, out)
			assert.Check(t, cmp.DeepEqual(extracted[:i], out), "partial %d", i)
		}
	})

	t.Run("offset, full", func(t *testing.T) {
		state := newDefaultState()
		in := one
		expected := state
		StateAddState(&expected, &in)
		assert.Check(t, expected != zero)

		extracted := make([]byte, 200)
		StateExtractBytes(&expected, extracted)

		out := make([]byte, 199)
		StateExtractAndAddStateToBytes(&state, &in, 1, out)

		assert.Check(t, cmp.DeepEqual(extracted[1:], out))
	})

	t.Run("all offsets, full", func(t *testing.T) {
		state := newDefaultState()
		in := one
		expected := state
		StateAddState(&expected, &in)
		assert.Assert(t, expected != zero)

		extracted := make([]byte, 200)
		StateExtractBytes(&expected, extracted)

		for i := 0; i < 200; i++ {
			expectedLen := 200 - i
			out := make([]byte, 200)
			StateExtractAndAddStateToBytes(&state, &in, i, out)
			assert.Check(t, cmp.DeepEqual(extracted[i:], out[:expectedLen]), "offset %d", i)
		}
	})

	t.Run("all offsets, partial", func(t *testing.T) {
		state := newDefaultState()
		in := one
		expected := state
		StateAddState(&expected, &in)
		assert.Assert(t, expected != zero)

		extracted := make([]byte, 200)
		StateExtractBytes(&expected, extracted)

		for i := 0; i < 200; i++ {
			out := make([]byte, 65)
			expectedLen := MinInt(200-i, len(out))
			StateExtractAndAddStateToBytes(&state, &in, i, out)
			assert.Check(t, cmp.DeepEqual(extracted[i:i+expectedLen], out[:expectedLen]), "offset %d, partial 65", i)
		}
	})
}
