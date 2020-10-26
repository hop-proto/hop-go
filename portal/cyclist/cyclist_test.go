package cyclist

import "testing"

func TestCyclistAbsorb(t *testing.T) {
	s := "let me absorb"
	c := Cyclist{}
	c.Initialize()
	c.Absorb([]byte(s))
	y := c.Squeeze(16)
	t.Log(y)
	t.Fail()
}
