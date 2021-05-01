package snp

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

func ParseSpacedHexString(spacedHex string) ([]byte, error) {
	r := strings.NewReader(spacedHex)
	s := bufio.NewScanner(r)
	s.Split(bufio.ScanWords)
	out := make([]byte, 0, len(spacedHex)/3+1)
	for s.Scan() {
		i, err := strconv.ParseUint(s.Text(), 16, 8)
		if err != nil {
			return nil, err
		}
		out = append(out, byte(i))
	}
	return out, nil
}

type TranscriptEntry struct {
	Action          string
	B               []byte
	Length          int
	ExplicitDecrypt bool
}

var reTranscript = regexp.MustCompile(`([\w-]+)\[(\d+)\]:(.*)$`)

func ParseTestTranscript(t *testing.T, r io.Reader) []TranscriptEntry {
	s := bufio.NewScanner(r)
	b := make([]byte, 0, 1024*2)
	s.Buffer(b, 1024*1024)
	s.Split(bufio.ScanLines)
	out := make([]TranscriptEntry, 0, 5)
	for s.Scan() {
		line := s.Text()
		matches := reTranscript.FindStringSubmatch(line)
		assert.Assert(t, cmp.Len(matches, 4), line)
		action := matches[1]
		length, err := strconv.Atoi(matches[2])
		assert.NilError(t, err, "invalid length %s", matches[2])
		value, err := ParseSpacedHexString(matches[3])
		assert.NilError(t, err, "invalid byte string value: %s", matches[3])
		assert.Assert(t, cmp.Len(value, length), "mismatched lengths")
		entry := TranscriptEntry{
			Action:          action,
			B:               value,
			Length:          length, // only matters for squeeze
			ExplicitDecrypt: true,
		}
		out = append(out, entry)
	}
	return out
}
