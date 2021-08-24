package transport

import (
	"testing"

	"gotest.tools/assert"
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
	assert.Check(t, checkPowerOf2(windowSize), "windowSize %d not power of 2")
	assert.Check(t, checkPowerOf2(numBlocks-1), "numBlocks-1 %d not power of 2", numBlocks-1)
}
