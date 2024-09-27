package common

import "io"

const bufferFull = -1

// RingBuffer is an in memory circular buffer implementing io.Writer and io.Reader
// It has amortized O(1) Writes and Reads.
type RingBuffer struct {
	buf   []byte
	start int
	end   int
}

var _ io.Reader = &RingBuffer{}
var _ io.Writer = &RingBuffer{}

func NewRingBuffer() RingBuffer {
	return RingBuffer{}
}

func (r *RingBuffer) Available() int {
	return len(r.buf) - r.Len()
}

func (r *RingBuffer) reallocate(size int) {
	// don't make the buffer smaller and discard data
	if size <= len(r.buf) {
		return
	}

	oldLen := r.Len()

	newSize := 16
	for newSize < size {
		newSize = newSize << 1
	}

	newBuf := make([]byte, newSize)
	r.Read(newBuf)

	r.buf = newBuf
	r.start = 0
	r.end = oldLen
}

func (r *RingBuffer) Len() int {
	if r.end == bufferFull {
		return len(r.buf)
	}

	if r.start < r.end {
		return r.end - r.start
	} else {
		return len(r.buf) - (r.start - r.end)
	}
}

// Write implements io.Writer.
func (r *RingBuffer) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	// ensure that there is enough space for the new data
	if len(b) > r.Available() || r.end == bufferFull {
		r.reallocate(r.Len() + len(b))
	}

	// Since we just reallocated, there is always enough space for the data.
	// This means that the only way we don't write the whole buffer
	// is if we need to wrap around to the beginning
	n = copy(r.buf[r.end:], b)
	if n < len(b) {
		copy(r.buf, b[n:])
	}

	r.end = (r.end + len(b)) % len(r.buf)
	if r.end == r.start {
		r.end = bufferFull
	}

	return len(b), nil
}

// Read implements io.Reader.
func (r *RingBuffer) Read(b []byte) (n int, err error) {
	if len(b) == 0 || len(r.buf) == 0 {
		return 0, nil
	}

	// --------S++++++++E--------
	if r.start < r.end {
		n = copy(b, r.buf[r.start:r.end])

		// ++++++E------------S++++++
	} else {
		n = copy(b, r.buf[r.start:])

		if n < len(b) {
			rangeEnd := r.end
			if rangeEnd == bufferFull {
				rangeEnd = r.start
			}
			n += copy(b[n:], r.buf[:rangeEnd])
		}

		if r.end == bufferFull {
			r.end = r.start
		}
	}

	r.start = (r.start + n) % len(r.buf)

	if r.start == r.end {
		r.start = 0
		r.end = 1
	}

	return n, nil
}
