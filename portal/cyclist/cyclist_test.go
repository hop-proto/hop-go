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
		t.Errorf("expected c.s[fb-8] = %.2x, got %.2x", expected23, c.s[23])
	}
	var expected24 uint64 = binary.LittleEndian.Uint64([]byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01})
	if c.s[24] != expected24 {
		t.Errorf("expected c.s[fb-1] = %.16d, got %.16x", expected24, c.s[24])
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

func TestCyclistAbsorb(t *testing.T) {
	k := newDefaultKey()
	s := "let me absorb"
	t.Log(len(s))
	c := Cyclist{}
	c.Initialize(k, nil, nil)
	c.Absorb([]byte(s))
	y := c.Squeeze(16)
	t.Logf("% x", y)
	t.Fail()
}
