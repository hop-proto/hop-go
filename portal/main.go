package main

import (
	"fmt"
)

// Phase is a enum used to represent internal state of Cyclist
type Phase int

// Cyclist has two phases: Up and Down. These are used internally by the
// permutation.
const (
	Up Phase = iota
	Down
)

type Mode int

const (
	Hash Mode = iota
	Key
)

const (
	// TODO(dadrian): These constants are wrong
	fB       = 1600
	rHash    = 128
	rAbsorb  = 128
	rSqueeze = 128
	lRatchet = 128
)

// Cyclist is an implementation of the public interface for a Cyclist duplex
// object as defined in https://eprint.iacr.org/2018/767.pdf.
type Cyclist struct {
	phase Phase
	mode  Mode
	s     [fB]byte
}

func Split(x []byte, blockSizeInBytes int) [][]byte {
	outputLen := len(x) / blockSizeInBytes
	if len(x)%blockSizeInBytes != 0 {
		outputLen++
	}
	out := make([][]byte, outputLen)
	for i := 0; i < outputLen; i++ {
		start := i * blockSizeInBytes
		end := start + blockSizeInBytes
		if end > len(x) {
			end = len(x)
		}
		out[i] = x[start:end]
	}
	return out
}

// NewCyclist returns an default-initialized Cyclist
//
// TODO(@dadrian): What are the parameters to Cyclist we're using?
func NewCyclist() (c *Cyclist) {
	return
}

func min(a int, b int) int {
	if a <= b {
		return a
	}
	return b
}

func (c *Cyclist) stateAddByteInPlace(src []byte, b byte, offset int) {
	src[offset] = src[offset] ^ b
}

func (c *Cyclist) stateAddBytes(src, b, out []byte) {
	length := len(b)
	for i := 0; i < length; i++ {
		out[i] = src[i] ^ b[i]
	}
}

func (c *Cyclist) f() {
	panic("unimplemented f")
}

func (c *Cyclist) absorbAny(x []byte, blockSize int, domain byte) {
	for i, xi := range Split(x, blockSize) {
		var domainFlag byte = 0
		if i == 0 {
			domainFlag = domain
		}
		if c.phase != Up {
			c.up(0, byte(0))
		}
		c.down(xi, domainFlag)
	}
}

func (c *Cyclist) absorbKey(key, id, counter []byte) {
	c.mode = Key
	// TODO(dadrian): What about R_{kin} and R_{kout}?
	// TODO(dadrian): Get rid of the malloc here
	input := make([]byte, 0, len(key)+len(id)+1)
	input = append(input, key...)
	input = append(input, id...)
	// TODO(dadrian): Enforce ID lengths?
	input = append(input, byte(len(id)))
	c.absorbAny(input, rAbsorb, 2)
	// TODO(dadrian): What are valid inputs for counter?
	if len(counter) > 0 {
		c.absorbAny(counter, 1, 0)
	}
}

func (c *Cyclist) crypt(in []byte, decrypt bool) []byte {
	// TODO(dadrian): Pass this in so that memory allocation isn't necessary
	out := make([]byte, len(in))
	splitIn := Split(in, rSqueeze)
	splitOut := Split(out, rSqueeze)
	// TODO(dadrian): This should be R_{kout}
	for i := range splitIn {
		// TODO(dadrian): Do this without multiplication?
		ii := splitIn[i]
		oi := splitOut[i]
		domainFlag := byte(0)
		if i == 0 {
			// TODO(dadrian): Confirm that this is hex
			domainFlag = 0x80
		}
		tmp := c.up(len(ii), domainFlag)
		c.stateAddBytes(ii, tmp, oi)
		pi := oi
		if !decrypt {
			pi = ii
		}
		c.down(pi, 0)
	}
	return out
}

func (c *Cyclist) squeezeAny(length int, domain byte) []byte {
	y := c.up(min(length, rSqueeze), 0)
	for {
		if len(y) >= length {
			break
		}
		c.down(nil, 0)
		// TODO(dadrian): Edit up to take the output buffer as a paramter, and
		// size y before passing it in.
		y2 := c.up(min(length-len(y), rSqueeze), 0)
		y = append(y, y2...)
	}
	return y
}

func (c *Cyclist) down(x []byte, domain byte) {
	c.stateAddBytes(c.s[:], x, c.s[:])
	c.stateAddByteInPlace(c.s[:], 1, len(x))
	cd := domain
	if c.mode == Hash {
		cd &= 1
	}
	c.stateAddByteInPlace(c.s[:], cd, fB-1)
	c.phase = Down
}

func (c *Cyclist) up(outputSize int, domain byte) []byte {
	if c.mode == Key {
		c.stateAddByteInPlace(c.s[:], domain, fB-1)
	}
	c.f()
	c.phase = Up
	// TODO(dadrian): Figure out how to do this without allocating memory
	out := make([]byte, outputSize)
	copy(out, c.s[:])
	return out
}

func (c *Cyclist) Absorb(x []byte) {
	c.absorbAny(x, rAbsorb, byte(3))
}

func (c *Cyclist) Encrypt(plaintext []byte) []byte {
	// TODO(dadrian): Pass the output buffer?
	if c.mode != Key {
		panic("can't encrypt in unkeyed mode")
	}
	return c.crypt(plaintext, false)
}

func (c *Cyclist) Decrypt(ciphertext []byte) []byte {
	return c.crypt(ciphertext, true)
}

func (c *Cyclist) Squeeze(length int) []byte {
	// TODO(dadrian): Is this a hex byte?
	return c.squeezeAny(length, 0x40)
}

func (c *Cyclist) SqueezeKey(length int) []byte {
	if c.mode != Key {
		panic("can't squeeze key in unkeyed mode")
	}
	// TODO(dadrian): Is this a hex byte?
	return c.squeezeAny(length, 0x20)
}

func (c *Cyclist) Ratchet() {
	if c.mode != Key {
		panic("can't ratched key in unkeyed mode")
	}
	// TODO(dadrian): Confirm is this is hex
	// TODO(dadrian): Define lRatchet
	c.absorbAny(c.squeezeAny(lRatchet, 0x10), rAbsorb, 0)
}

func main() {
	fmt.Println("portal!")
}
