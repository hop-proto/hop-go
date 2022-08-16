package codex

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
)

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

const (
	stdoutFlag = byte(1)
	stderrFlag = byte(2)
)

type prefixWriter struct {
	writer  io.Writer
	prefix  byte
	bufLock sync.Mutex
	buf     *bytes.Buffer
}

func newPrefixWriter(writer io.Writer, prefix byte) *prefixWriter {
	return &prefixWriter{
		writer,
		prefix,
		sync.Mutex{},
		&bytes.Buffer{},
	}
}

// NewStdoutWriter wraps writer to send data tagged as stdout--it should be
// matched using NewSplitReader on the receiving side
func NewStdoutWriter(writer io.Writer) io.Writer {
	return newPrefixWriter(writer, stdoutFlag)
}

// NewStderrWriter wraps writer to send data tagged as stderr--it should be
// matched using NewSplitReader on the receiving side
func NewStderrWriter(writer io.Writer) io.Writer {
	return newPrefixWriter(writer, stderrFlag)
}

func (w *prefixWriter) Write(b []byte) (n int, err error) {
	w.bufLock.Lock()
	defer w.bufLock.Unlock()
	if w.buf.Cap() < min(len(b), math.MaxUint16)+3 {
		w.buf.Grow(min(len(b), math.MaxUint16))
	}
	// If we end up using this for something besides splitting stdout/stderr,
	// it's worth considering whether to call the underlying .Write when
	// len(b) == 0
	for len(b) > 0 {
		w.buf.Reset()
		w.buf.WriteByte(w.prefix)
		dataLength := uint16(min(len(b), math.MaxUint16))
		binary.Write(w.buf, binary.BigEndian, dataLength)
		w.buf.Write(b)
		written, e := w.writer.Write(w.buf.Bytes())
		n += max(written-3, 0)
		if e != nil {
			err = e
			return
		}
		b = b[dataLength:]
	}
	return
}

// SplitReader implements io.Reader--it should be matched with writers using
// NewStdoutWriter and NewStderrWriter on the sending side;
var ErrInvalidSplitHeader = errors.New("invalid Split header")

// TODO(drebelsky): consider timeouts

// newSplitReader splits an io.Reader that is reading data sent by
// NewStdoutWriter and NewStderrWriter into two io.Readers, one for stdout and
// one for stderr; note that Stdout and Stderr can block each other
func newSplitReader(reader io.Reader) (stdout io.Reader, stderr io.Reader) {
	outr, outw := io.Pipe()
	errr, errw := io.Pipe()
	go func() {
		defer func() {
			outw.Close()
			errw.Close()
		}()
		header := make([]byte, 3)
		b := make([]byte, math.MaxUint16)
		for {
			_, err := io.ReadFull(reader, header)
			if err != nil {
				break
			}
			length := binary.BigEndian.Uint16(header[1:])
			n, err := io.ReadFull(reader, b[:length])
			if header[0] == stdoutFlag {
				outw.Write(b[:n])
			} else {
				errw.Write(b[:n])
			}
			if err != nil {
				break
			}
		}
	}()
	return outr, errr
}
