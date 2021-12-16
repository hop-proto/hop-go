package transport

const (
	numBlocks  = 8
	blockSize  = 64
	windowSize = (numBlocks - 1) * blockSize

	locationMask = blockSize - 1
	locationBits = 6
	indexMask    = numBlocks - 1
)

// SlidingWindow implements the replay detection algorithm from RFC 6479 using a
// receive window of 448, and 512 bits of state, with a 64-bit block.
//
// https://www.rfc-editor.org/rfc/rfc6479.txt
type SlidingWindow struct {
	blocks [numBlocks]uint64
	wt     uint64
}

// Check returns true if the sequence number is allowed.
func (s SlidingWindow) Check(seq uint64) (ok bool) {
	// Larger is always OK
	if seq > s.wt {
		return true
	}
	// Below the bottom of the window is always bad
	if seq+windowSize < s.wt {
		return false
	}
	bitIndex := seq & locationMask
	blockIndex := (seq >> locationBits) & indexMask

	// Allowed if the bit hasn't been set yet
	return s.blocks[blockIndex]&(1<<bitIndex) == 0
}

// Mark advances the sliding window, if needed, and sets the sequence number as
// seen.
func (s *SlidingWindow) Mark(seq uint64) {
	// If it's older than the bottom of the window, nothing to do.
	if seq+windowSize < s.wt {
		return
	}
	unmaskedBlockIndex := (seq >> locationBits)
	if seq > s.wt {
		unmaskedCurrentIndex := (s.wt >> locationBits)
		diff := unmaskedBlockIndex - unmaskedCurrentIndex
		if diff > numBlocks {
			diff = numBlocks
		}
		for i := uint64(0); i < diff; i++ {
			idx := (i + unmaskedCurrentIndex + 1) & indexMask
			s.blocks[idx] = 0
		}
		s.wt = seq
	}

	index := unmaskedBlockIndex & indexMask
	location := seq & locationMask
	s.blocks[index] |= (1 << location)
}
