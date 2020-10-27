package cyclist

import (
	"bytes"
	"encoding/binary"
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
	b      []byte
	length int
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

func runTranscript(t *testing.T, test *cyclistTranscriptTest, initiator, responder *Cyclist) {
	for i, entry := range test.transcript {
		t.Logf("test %s, entry %d", test.name, i)
		switch entry.action {
		case "absorb":
			initiator.Absorb(entry.b)
			responder.Absorb(entry.b)
			assertEquivalentState(t, initiator, responder)
		case "squeeze":
			ib := make([]byte, entry.length)
			rb := make([]byte, entry.length)
			initiator.Squeeze(ib)
			responder.Squeeze(rb)
			assertEquivalentState(t, initiator, responder)
			if !bytes.Equal(ib, rb) {
				t.Errorf("expected squeeze % x, got % x", ib, rb)
			}
		case "encrypt-ir":
			ciphertext := make([]byte, len(entry.b))
			plaintext := make([]byte, len(ciphertext))
			initiator.Encrypt(ciphertext, entry.b)
			responder.Decrypt(plaintext, ciphertext)
			assertEquivalentState(t, initiator, responder)
			if !bytes.Equal(entry.b, plaintext) {
				t.Errorf("expected decrypted data % x to equal input % x", plaintext, entry.b)
			}
		case "encrypt-ri":
			ciphertext := make([]byte, len(entry.b))
			plaintext := make([]byte, len(ciphertext))
			responder.Encrypt(ciphertext, entry.b)
			initiator.Decrypt(plaintext, ciphertext)
			assertEquivalentState(t, initiator, responder)
			if !bytes.Equal(entry.b, plaintext) {
				t.Errorf("expected decrypted data % x to equal input % x", plaintext, entry.b)
			}
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
