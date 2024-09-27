package common

import (
	"testing"

	"gotest.tools/assert"
)

func TestRingBuffer(t *testing.T) {
	t.Run("basic", BasicTest)
	t.Run("fill buffer", FillBuffer)
	t.Run("reallocations", Reallocations)
	t.Run("wraparound", WrapAround)
}

// Test simple reads and writes
func BasicTest(t *testing.T) {
	rb := NewRingBuffer()
	data := []byte("hello world!!!")

	n, err := rb.Write(data)
	assert.NilError(t, err)
	assert.DeepEqual(t, n, len(data))
	assert.DeepEqual(t, rb.start, 0)
	assert.DeepEqual(t, rb.end, len(data))

	buf := make([]byte, len(data)+5)
	n, err = rb.Read(buf)
	assert.NilError(t, err)
	assert.DeepEqual(t, n, len(data))
	assert.DeepEqual(t, rb.start, 0)
	assert.DeepEqual(t, rb.end, 1)
}

// Fill the buffer to ensure that writing a power of 2
// bytes to the buffer doesn't allocate more memory than needed
func FillBuffer(t *testing.T) {
	rb := NewRingBuffer()
	data := []byte{0, 1, 2, 3, 4, 5, 6}

	n, err := rb.Write(data)
	assert.NilError(t, err)
	assert.DeepEqual(t, n, len(data))
	assert.DeepEqual(t, len(rb.buf), 8)
	assert.DeepEqual(t, rb.start, 0)
	assert.DeepEqual(t, rb.end, 7)

	buf := make([]byte, 4)
	n, err = rb.Read(buf)
	assert.NilError(t, err)
	assert.DeepEqual(t, buf, data[:4])

	n, err = rb.Read(buf)
	assert.NilError(t, err)
	assert.DeepEqual(t, buf[:3], data[4:])
}

func Reallocations(t *testing.T) {
	rb := RingBuffer{}

	assert.DeepEqual(t, len(rb.buf), 0)

	// Write 1 byte
	n, err := rb.Write([]byte{1})
	assert.NilError(t, err)
	assert.DeepEqual(t, n, 1)
	assert.DeepEqual(t, len(rb.buf), 16)

	// Write 15 more bytes, filling the buffer
	n, err = rb.Write(make([]byte, 15))
	assert.NilError(t, err)
	assert.DeepEqual(t, n, 15)
	assert.DeepEqual(t, rb.Len(), 16)
	assert.DeepEqual(t, len(rb.buf), 16)

	// Write 1 more byte triggering a reallocation
	n, err = rb.Write([]byte{1})
	assert.NilError(t, err)
	assert.DeepEqual(t, n, 1)
	assert.DeepEqual(t, rb.Len(), 17)
	assert.DeepEqual(t, len(rb.buf), 32)

	// Read one byte from the front
	n, err = rb.Read(make([]byte, 1))
	assert.NilError(t, err)
	assert.DeepEqual(t, n, 1)
	assert.DeepEqual(t, rb.Len(), 16)
	assert.DeepEqual(t, rb.start, 1)
	assert.DeepEqual(t, rb.end, 17)

	// Write 16 more bytes to fill a 32 byte buffer
	n, err = rb.Write(make([]byte, 16))
	assert.NilError(t, err)
	assert.DeepEqual(t, n, 16)
	assert.DeepEqual(t, rb.Len(), 32)
	assert.DeepEqual(t, len(rb.buf), 32)
	assert.DeepEqual(t, rb.start, 1)
	assert.DeepEqual(t, rb.end, bufferFull)

	// Read one byte from the front
	n, err = rb.Read(make([]byte, 1))
	assert.NilError(t, err)
	assert.DeepEqual(t, n, 1)
	assert.DeepEqual(t, rb.Len(), 31)
	assert.DeepEqual(t, rb.start, 2)
	assert.DeepEqual(t, rb.end, 1)
}

// Test Read and writes when the buffer has wrapped around
func WrapAround(t *testing.T) {
	rb := &RingBuffer{}

	// Fill the buffer to allocate enough memory
	n, err := rb.Write(make([]byte, 32))
	assert.NilError(t, err)
	assert.DeepEqual(t, n, 32)
	assert.DeepEqual(t, len(rb.buf), 32)

	n, err = rb.Read(make([]byte, 24))
	assert.NilError(t, err)
	assert.DeepEqual(t, n, 24)
	assert.DeepEqual(t, rb.start, 24)
	assert.DeepEqual(t, rb.end, 0)

	n, err = rb.Write(make([]byte, 8))
	assert.NilError(t, err)
	assert.DeepEqual(t, n, 8)
	assert.DeepEqual(t, rb.start, 24)
	assert.DeepEqual(t, rb.end, 8)
	assert.DeepEqual(t, rb.Len(), 16)
	assert.DeepEqual(t, rb.Available(), 16)

	// State of the ringbuf now
	// +++++++E---------------S+++++++

	n, err = rb.Read(make([]byte, 12))
	assert.NilError(t, err)
	assert.DeepEqual(t, n, 12)
	assert.DeepEqual(t, rb.start, 4)
	assert.DeepEqual(t, rb.end, 8)
	assert.DeepEqual(t, rb.Len(), 4)
	assert.DeepEqual(t, rb.Available(), 28)
}
