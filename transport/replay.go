package transport

const (
	numBlocks  = 5
	blockSize  = 64
	windowSize = (numBlocks - 1) * blockSize
	extraSpace = blockSize
)

type SlidingWindow struct {
	blocks [blockSize]uint64
	wb, wt uint64
}

func (s SlidingWindow) Check(seq uint64) (ok bool) {
	// Larger is always OK
	if seq > s.wt {
		return true
	}
	// Below the bottom of the window is always bad
	if seq+windowSize < s.wt {
		return false
	}
	return true
}
