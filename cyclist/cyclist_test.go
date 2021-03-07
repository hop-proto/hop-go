package cyclist

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func newDefaultKey() []byte {
	out := make([]byte, 32)
	for i := 0; i < len(out); i++ {
		out[i] = byte(i)
	}
	return out
}

func assertLeadingStateEquals(t *testing.T, actual, expected []uint64) {
	length := min(len(actual), len(expected))
	for i := 0; i < length; i++ {
		if actual[i] != expected[i] {
			t.Errorf("index %d: actual %.16x, expected %.16x", i, actual[i], expected[i])
		}
	}
	if len(expected) > len(actual) {
		t.Errorf("actual len %d, expected len() <= %d", len(actual), len(expected))
	}
}

func TestStateAddBytes(t *testing.T) {
	var b []byte
	var u []uint64
	c := Cyclist{}
	c.InitializeEmpty()
	b = []byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00}
	c.stateAddBytes(b[0:4])
	u = []uint64{binary.LittleEndian.Uint64(b)}
	assertLeadingStateEquals(t, c.s[:], u)
	b = []byte{0x01, 0x02, 0x03, 0x04, 0x0A, 0x0B, 0x0C, 0x0D, 0x05, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00}
	c.stateAddBytes(b)
	u = []uint64{
		binary.LittleEndian.Uint64([]byte{0x01 ^ 0x01, 0x02 ^ 0x02, 0x03 ^ 0x03, 0x04 ^ 0x04, 0x0A, 0x0B, 0x0C, 0x0D}),
		binary.LittleEndian.Uint64([]byte{0x05, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00}),
	}
	assertLeadingStateEquals(t, c.s[:], u)
}

func TestStateAddByte(t *testing.T) {
	c := Cyclist{}
	c.InitializeEmpty()
	c.stateAddByte(0x01, fB-1)
	c.stateAddByte(0x02, fB-2)
	c.stateAddByte(0x08, fB-8)
	c.stateAddByte(0x09, fB-9)
	assertLeadingStateEquals(t, c.s[:], make([]uint64, 23))
	var expected23 uint64 = binary.LittleEndian.Uint64([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09})
	if c.s[23] != expected23 {
		t.Errorf("expected c.s[fb-8] = %.16x, got %.16x", expected23, c.s[23])
	}
	var expected24 uint64 = binary.LittleEndian.Uint64([]byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01})
	if c.s[24] != expected24 {
		t.Errorf("expected c.s[fb-1] = %.16x, got %.16x", expected24, c.s[24])
	}
	y := make([]byte, fB)
	c.stateCopyOut(y)
	expectedBytes := []byte{0x09, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01}
	if !bytes.Equal(expectedBytes, y[fB-9:fB]) {
		t.Errorf("expected last nine bytes copied out %.16x, actual %.16x", expectedBytes, y)
	}

}

func TestStateCopyOut(t *testing.T) {
	c := Cyclist{}
	c.InitializeEmpty()
	b1 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	b2 := []byte{0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00}
	c.s[0] = binary.LittleEndian.Uint64(b1)
	c.s[1] = binary.LittleEndian.Uint64(b2)
	out := make([]byte, 13)
	c.stateCopyOut(out)
	expected := append(b1, b2...)
	if !bytes.Equal(expected[0:13], out) {
		t.Errorf("expected %.16x, actual %.x16x", expected, out)
	}
}

func TestCyclistFromC(t *testing.T) {
	k := newDefaultKey()
	s := "let me absorb"
	c := Cyclist{}
	c.Initialize(k, nil, nil)
	c.Absorb([]byte(s))
	y := make([]byte, 16)
	c.Squeeze(y)
	t.Logf("% x", y)
	// expectedY generated from C implementation
	expectedY := []byte{0x53, 0xe5, 0x4c, 0x73, 0x85, 0x30, 0x95, 0x36, 0xbf, 0x89, 0x5c, 0xff, 0x0f, 0x59, 0x3e, 0x51}
	if !bytes.Equal(expectedY, y) {
		t.Errorf("squeeze: expected % x, got % x", expectedY, y)
	}
	s2 := "we own things, but we have hidden them."
	cout := make([]byte, len(s2))
	c.Encrypt(cout, []byte(s2))
	// expectedCout generated from C implementation
	expectedCout := []byte{0xf3, 0xa0, 0x12, 0x25, 0x1d, 0xd2, 0xde, 0x91, 0x73, 0xa8, 0xa0, 0x3c, 0x2b, 0xd9, 0x88, 0x52, 0xa9, 0x49, 0xff, 0x35, 0x2b, 0xcc, 0xf5, 0x21, 0x7e, 0xba, 0x17, 0x32, 0x5b, 0xf6, 0xe8, 0x21, 0x1b, 0x1b, 0x7b, 0x0a, 0x11, 0x3d, 0x2f}
	if !bytes.Equal(expectedCout, cout) {
		t.Errorf("encrypt: expected % x, got % x", expectedCout, cout)
	}
}

type cyclistTranscriptEntry struct {
	action string

	// Input for absorb, encrypt, and decrypt
	// Optional expected value for squeeze
	b []byte

	// Output size for squeeze
	length int

	// true if decrypt is a separate stage in the transcript from encrypt. When
	// false, the tests will automatically have the opposite side decrypt any
	// input to encrypt.
	explicitDecrypt bool
}

type cyclistTranscriptTest struct {
	name       string
	transcript []cyclistTranscriptEntry
}

func assertEquivalentState(t *testing.T, a, b *Cyclist) {
	var ab [200]byte
	var bb [200]byte
	a.stateCopyOut(ab[:])
	b.stateCopyOut(bb[:])
	if !bytes.Equal(ab[:], bb[:]) {
		t.Errorf("cyclist state: expected % x, got % x", ab, bb)
	}
}

const reTranscriptString = `([\w-]+)\[(\d+)\]:(.*)$`

var reTranscript = regexp.MustCompile(reTranscriptString)

func parseSpacedHexString(spacedHex string) ([]byte, error) {
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

func parseTranscript(r io.Reader) ([]cyclistTranscriptEntry, error) {
	s := bufio.NewScanner(r)
	b := make([]byte, 0, 1024*2)
	s.Buffer(b, 1024*1024)
	s.Split(bufio.ScanLines)
	out := make([]cyclistTranscriptEntry, 0, 5)
	for s.Scan() {
		line := s.Text()
		matches := reTranscript.FindStringSubmatch(line)
		if len(matches) != 4 {
			return nil, fmt.Errorf("invalid line: %s", line)
		}
		action := matches[1]
		length, err := strconv.Atoi(matches[2])
		if err != nil {
			return nil, fmt.Errorf("invalid length: %s", matches[2])
		}
		value, err := parseSpacedHexString(matches[3])
		if err != nil {
			return nil, fmt.Errorf("invalid byte string value: %s", matches[3])
		}
		if len(value) != length {
			return nil, fmt.Errorf("expected %d bytes, got %d", length, len(value))
		}
		entry := cyclistTranscriptEntry{
			action:          action,
			b:               value,
			length:          length, // only matters for squeeze
			explicitDecrypt: true,
		}
		out = append(out, entry)
	}
	return out, nil
}

func runTranscript(t *testing.T, test *cyclistTranscriptTest, initiator, responder *Cyclist) {
	var previousPlaintext []byte
	for i, entry := range test.transcript {
		t.Logf("test %s, entry %d", test.name, i)
		switch entry.action {
		case "absorb":
			initiator.Absorb(entry.b)
			responder.Absorb(entry.b)
			assertEquivalentState(t, initiator, responder)
		case "squeeze":
			iy := make([]byte, entry.length)
			ry := make([]byte, entry.length)
			initiator.Squeeze(iy)
			responder.Squeeze(ry)
			assertEquivalentState(t, initiator, responder)
			if len(entry.b) > 0 {
				if !bytes.Equal(entry.b, iy) {
					t.Errorf("expected squeeze % x, got % x", entry.b, iy)
				}
			}
			if !bytes.Equal(iy, ry) {
				t.Errorf("expected equal squeezes, initiator gave % x, responder gave % x", iy, ry)
			}
		case "encrypt-ir":
			ciphertext := make([]byte, len(entry.b))
			initiator.Encrypt(ciphertext, entry.b)
			previousPlaintext = entry.b
			if !entry.explicitDecrypt {
				plaintext := make([]byte, len(ciphertext))
				responder.Decrypt(plaintext, ciphertext)
				assertEquivalentState(t, initiator, responder)
				if !bytes.Equal(entry.b, plaintext) {
					t.Errorf("expected decrypted data % x to equal input % x", plaintext, entry.b)
				}
			}
		case "decrypt-ir":
			plaintext := make([]byte, len(entry.b))
			responder.Decrypt(plaintext, entry.b)
			if !bytes.Equal(previousPlaintext, plaintext) {
				t.Errorf("expected decrypted data % x, got % x", previousPlaintext, plaintext)
			}
			assertEquivalentState(t, initiator, responder)
		case "encrypt-ri":
			ciphertext := make([]byte, len(entry.b))
			responder.Encrypt(ciphertext, entry.b)
			previousPlaintext = entry.b
			if !entry.explicitDecrypt {
				plaintext := make([]byte, len(ciphertext))
				initiator.Decrypt(plaintext, ciphertext)
				assertEquivalentState(t, initiator, responder)
				if !bytes.Equal(entry.b, plaintext) {
					t.Errorf("expected decrypted data % x to equal input % x", plaintext, entry.b)
				}
			}
		case "decrypt-ri":
			plaintext := make([]byte, len(entry.b))
			initiator.Decrypt(plaintext, entry.b)
			if !bytes.Equal(previousPlaintext, plaintext) {
				t.Errorf("expected decrypted data % x, got % x", previousPlaintext, plaintext)
			}
			assertEquivalentState(t, initiator, responder)
		default:
			t.Fatalf("unknown action %s", entry.action)
		}
	}
}

func TestCyclistEncryptDecrypt(t *testing.T) {
	client := Cyclist{}
	client.Initialize(newDefaultKey(), nil, nil)
	server := Cyclist{}
	server.Initialize(newDefaultKey(), nil, nil)
	test := cyclistTranscriptTest{
		name: "encrypt-decrypt",
		transcript: []cyclistTranscriptEntry{
			{
				action: "absorb",
				b:      []byte("the creature has requested gentle handpats."),
			},
			{
				action: "encrypt-ir",
				b:      []byte("for how long?"),
			},
			{
				action: "encrypt-ri",
				b:      []byte("until one of us perishes."),
			},
			{
				action: "absorb",
				b:      []byte("a life well spent!"),
			},
			{
				action: "squeeze",
				length: 100,
			},
		},
	}
	runTranscript(t, &test, &client, &server)
}

func TestCyclistAgainstReference(t *testing.T) {
	implementations := []string{
		"xkcp",
	}
	for _, implementation := range implementations {
		path := fmt.Sprintf("testdata/%s.txt", implementation)
		w, err := os.Open(path)
		if err != nil {
			t.Fatalf("unable to open %s: %s", path, err)
		}
		transcript, err := parseTranscript(w)
		if err != nil {
			t.Fatalf("unable to parse transcript %s: %s", path, err)
		}
		test := cyclistTranscriptTest{
			name:       implementation,
			transcript: transcript,
		}
		initiator := Cyclist{}
		initiator.Initialize(newDefaultKey(), nil, nil)
		responder := Cyclist{}
		responder.Initialize(newDefaultKey(), nil, nil)
		runTranscript(t, &test, &initiator, &responder)
	}
}
