package transport

import (
	"math"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

func checkPowerOf2(n int) bool {
	d := 1
	matches := 0
	for i := 0; i < 32; i++ {
		if n == d {
			matches++
		}
		d <<= 1
	}
	return matches == 1
}

func TestReplayConstant(t *testing.T) {
	assert.Check(t, checkPowerOf2(blockSize), "windowSize %d not power of 2")
	assert.Check(t, checkPowerOf2(numBlocks), "numBlocks %d not power of 2", numBlocks)
	assert.Check(t, cmp.Equal(uint64(math.Pow(2, locationBits)), uint64(64)), "2^locationBits should be blockSize")
}

func TestCheck(t *testing.T) {
	s := SlidingWindow{}

	// It starts empty
	for i := uint64(0); i < 2*windowSize; i++ {
		assert.Assert(t, cmp.Equal(true, s.Check(i)))
	}

	// Check that mark flips the bit
	for i := uint64(0); i < 2*windowSize; i++ {
		s.Mark(i)
		assert.Assert(t, cmp.Equal(false, s.Check(i)))
	}

	// Flip a big big
	big := uint64(0xDEADBEEF)
	s.Mark(big)

	// The window should have advanced
	bottom := big - windowSize
	assert.Assert(t, cmp.Equal(false, s.Check(bottom-1)))
	for i := bottom; i < big; i++ {
		assert.Assert(t, cmp.Equal(true, s.Check(i)))
	}
	assert.Assert(t, cmp.Equal(false, s.Check(big)))

	// Flipping a big inside the window should only flip that bit without
	// advancing the window.
	inside := big - 35
	s.Mark(inside)
	assert.Assert(t, cmp.Equal(false, s.Check(inside)))
	assert.Assert(t, cmp.Equal(false, s.Check(big)))
	assert.Assert(t, cmp.Equal(false, s.Check(bottom-1)))
	for i := bottom; i < big+1; i++ {
		seen := (i == inside || i == big)
		assert.Assert(t, cmp.Equal(!seen, s.Check(i)))
	}

	// The window should advance by 1 if the top moves by 1
	stillAllowed := bottom
	assert.Assert(t, cmp.Equal(true, s.Check(stillAllowed)))
	s.Mark(big + 1)
	assert.Assert(t, cmp.Equal(false, s.Check(stillAllowed)))
}
