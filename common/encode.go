package common

import (
	"encoding/binary"
	"io"
	"strings"
)

// WriteString writes a string preceded by its length.
func WriteString(s string, w io.Writer) (int64, error) {
	var written int64
	// write length of string as one byte
	n, err := w.Write([]byte{byte(len(s))})
	written += int64(n)
	if err != nil {
		return written, err
	}
	n, err = w.Write([]byte(s))
	written += int64(n)
	if err != nil {
		return written, err
	}
	return written, nil
}

// ReadString reads a variable length string
func ReadString(r io.Reader) (string, int64, error) {
	var bytesRead int64
	// read len
	var len byte
	err := binary.Read(r, binary.BigEndian, &len)
	if err != nil {
		return "", bytesRead, err
	}
	bytesRead++
	// read string
	builder := strings.Builder{}
	copied, err := io.CopyN(&builder, r, int64(len))
	bytesRead += copied
	return builder.String(), bytesRead, err

}
