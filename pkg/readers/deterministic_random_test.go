package readers

import (
	"math"
	"testing"
)

func TestDeterministicCoinFlipper_Repeatability(t *testing.T) {
	seed := uint64(42)
	bits := 3
	flipper1 := NewDeterministicCoinFlipper(seed, bits, true)
	flipper2 := NewDeterministicCoinFlipper(seed, bits, false)

	const n = 100
	for i := 0; i < n; i++ {
		if flipper1.Flip() != !flipper2.Flip() {
			t.Fatalf("flip mismatch at index %d", i)
		}
	}
}

func TestDeterministicCoinFlipper_BiasCounts(t *testing.T) {
	seed := uint64(12345)
	const totalFlips = 256

	type biasCase struct {
		bits          int
		expectedHeads int
	}
	testCases := []biasCase{
		{1, 128},
		{2, 64},
		{3, 32},
		{4, 16},
	}

	for _, tc := range testCases {
		flipper := NewDeterministicCoinFlipper(seed, tc.bits, true)
		count := 0
		for i := 0; i < totalFlips; i++ {
			if flipper.Flip() {
				count++
			}
		}
		difference := math.Abs(float64(count - tc.expectedHeads))
		epsilon := max(float64(tc.expectedHeads)*0.1, 4)
		if difference > epsilon {
			t.Errorf("with %d bits, expected %d heads, got %d (difference %f, tolerance %f)", tc.bits, tc.expectedHeads, count, difference, epsilon)
		}
	}
}
