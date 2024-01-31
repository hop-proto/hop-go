package tubes

import (
    "sync"
    "errors"
)

var bufferFull error

func init() {
    bufferFull = errors.New("Buffer is full")
}

type buffer struct {
	buffer [][]byte
	start  int
	size   int
	m      sync.Mutex
}


func (b *buffer) Write(data []byte) error {
	b.m.Lock()
	defer b.m.Unlock()
	if b.size == len(b.buffer) {
	    return bufferFull
    }
    b.buffer[(b.start + b.size) % len(b.buffer)] = data
    b.size++
    return nil
}

func (b *buffer) Read(data []byte) (n int, err error) {
	b.m.Lock()
	defer b.m.Unlock()
    data_length := len(data)
	for n < data_length && b.size > 0 { 
        written := copy(data[n:], b.buffer[b.start])
        if written < len(b.buffer[b.start]) {
            b.buffer[b.start] = b.buffer[b.start][written:]
        } else {
            b.start = (b.start + 1) % len(b.buffer)
            b.size--
        }
        n += written
    }
	return n, nil
}

func (b *buffer) Len() int {
	b.m.Lock()
	defer b.m.Unlock()
	return b.size
}

