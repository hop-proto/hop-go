package cyclist

import (
	"bytes"
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
	c := Cyclist{}
	c.InitializeEmpty()
	c.stateAddBytes([]byte{0x01, 0x02, 0x03, 0x04})
	assertLeadingStateEquals(t, c.s[:], []uint64{0x0000000004030201})
	c.stateAddBytes([]byte{0x00, 0x00, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x05, 0x06, 0x07})
	assertLeadingStateEquals(t, c.s[:], []uint64{0x0D0C0B0A04030201, 0x0000000000070605})
}

func TestStateAddByte(t *testing.T) {
	c := Cyclist{}
	c.InitializeEmpty()
	c.stateAddByte(0x01, fB-1)
	c.stateAddByte(0x02, fB-2)
	c.stateAddByte(0x08, fB-8)
	c.stateAddByte(0x09, fB-9)
	assertLeadingStateEquals(t, c.s[:], make([]uint64, 23))
	//var expected23 uint64 = 0x09
	var expected23 uint64 = 0x0900000000000000
	if c.s[23] != expected23 {
		t.Errorf("expected c.s[fb-8] = %.2x, got %.2x", expected23, c.s[23])
	}
	//var expected24 uint64 = 0x0800000000000201
	var expected24 uint64 = 0x0102000000000008
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
	c.s[0] = 0x0102030405060708
	c.s[1] = 0x090A0B0C0D0E0F00
	out := make([]byte, 2*8)
	c.stateCopyOut(out)
	expected := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09}
	if !bytes.Equal(expected, out) {
		t.Errorf("expected %.16x, actual %.x16x", expected, out)
	}
}

func TestCyclistAbsorb(t *testing.T) {
	k := newDefaultKey()
	s := "let me absorb"
	t.Log(len(s))
	c := Cyclist{}
	c.Initialize(k, nil, nil)
	t.Logf("%17x", c.s)
	c.Absorb([]byte(s))
	t.Logf("%17x", c.s)
	y := c.Squeeze(16)
	t.Logf("% x", y)
	t.Fail()
}
