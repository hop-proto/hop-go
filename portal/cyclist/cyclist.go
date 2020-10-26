package cyclist

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
	fB       = 1600 / 8
	rHash    = 1088 / 8
	rKin     = 1088 / 8
	rKout    = 1088 / 8
	lRatchet = 256 / 8
)

// Cyclist is an implementation of the public interface for a Cyclist duplex
// object as defined in https://eprint.iacr.org/2018/767.pdf.
type Cyclist struct {
	phase             Phase
	mode              Mode
	rAbsorb, rSqueeze int
	s                 [25]uint64
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

func (c *Cyclist) InitializeEmpty() {
	c.mode = Hash
	c.rAbsorb = rHash
	c.rSqueeze = rHash
}

func (c *Cyclist) Initialize(key, id, counter []byte) {
	c.mode = Hash
	c.phase = Up
	c.rAbsorb = rHash
	c.rSqueeze = rHash
	if len(key) > 0 {
		c.absorbKey(key, id, counter)
	}
}

func min(a int, b int) int {
	if a <= b {
		return a
	}
	return b
}

func (c *Cyclist) arrayAddByteInPlace(src []byte, b byte, offset int) {
	src[offset] = src[offset] ^ b
}

func (c *Cyclist) arrayAddBytes(src, b, out []byte) {
	length := len(b)
	for i := 0; i < length; i++ {
		out[i] = src[i] ^ b[i]
	}
}

func (c *Cyclist) stateAddByte(b byte, offset int) {
	// TODO(dadrian): Remove the multiplication
	idx := offset / 8
	/*
		// Big Endian?
		byteIdx := 7 - (offset % 8)
		shift := byteIdx * 8
	*/
	// Little Endian?
	byteIdx := offset % 8
	shift := byteIdx * 8
	x := uint64(b) << shift
	c.s[idx] ^= x
}

func (c *Cyclist) stateAddBytes(b []byte) {
	// TODO(dadrian): This is almost definitely wrong.
	// TODO(dadrian): Unit test this.
	length := len(b)
	i := 0
	for stateIdx := 0; stateIdx < 25; stateIdx++ {
		/*
			Big Endian?
			for shift := 56; shift >= 0; shift -= 8 {
				c.s[stateIdx] ^= uint64(b[i]) << shift
				i++
				if i >= length {
					return
				}
			}
		*/
		// Little Endian?
		for shift := 0; shift < 64; shift += 8 {
			c.s[stateIdx] ^= uint64(b[i]) << shift
			i++
			if i >= length {
				return
			}
		}

	}
}

// stateCopyOut writes the first len(out) bytes of the state into out. If s is
// shorter than out, only len(s) bytes will be written.
func (c *Cyclist) stateCopyOut(out []byte) {
	length := len(out)
	i := 0
	for stateIdx := 0; stateIdx < 25; stateIdx++ {
		for shift := 0; shift < 64; shift += 8 {
			if i >= length {
				return
			}
			out[i] = byte(c.s[stateIdx] >> shift)
			i++
		}
	}
}

func (c *Cyclist) f() {
	keccakF1600(&c.s)
}

func (c *Cyclist) absorbAny(x []byte, r int, cd byte) {
	xLen := len(x)
	start := 0
	for {
		if c.phase != Up {
			c.up(nil, 0)
		}
		splitLen := min(xLen, r)
		c.down(x[start:splitLen], cd)
		cd = 0
		start += splitLen
		xLen -= splitLen
		if xLen == 0 {
			break
		}
	}
}

func (c *Cyclist) absorbKey(key, id, counter []byte) {
	c.mode = Key
	c.rAbsorb = rKin
	c.rSqueeze = rKout

	var kid [rKin]byte
	klen := len(key)
	idlen := len(id)
	// TODO(dadrian): Get rid of the malloc here
	copy(kid[0:], key)
	copy(kid[klen:], id)
	kid[klen+idlen] = byte(idlen)
	c.absorbAny(kid[0:klen+idlen+1], c.rAbsorb, 0x02)
	// TODO(dadrian): What are valid inputs for counter?
	if len(counter) > 0 {
		c.absorbAny(counter, 1, 0x00)
	}
}

func (c *Cyclist) crypt(in []byte, decrypt bool) []byte {
	// TODO(dadrian): Pass this in so that memory allocation isn't necessary
	out := make([]byte, len(in))
	splitIn := Split(in, rKout)
	splitOut := Split(out, rKout)
	cu := byte(0x80)
	for i := range splitIn {
		// TODO(dadrian): Do this without multiplication or allocation?
		ii := splitIn[i]
		oi := splitOut[i]
		tmp := make([]byte, len(ii))
		c.up(tmp, cu)
		c.arrayAddBytes(ii, tmp, oi)
		pi := oi
		if !decrypt {
			pi = ii
		}
		c.down(pi, 0)
		cu = 0
	}
	return out
}

func (c *Cyclist) squeezeAny(yLen int, domain byte) []byte {
	// TODO(dadrian): Remove allocation
	y := make([]byte, yLen)
	upLen := min(yLen, c.rSqueeze)
	c.up(y[0:upLen], 0)
	start := upLen
	yLen -= upLen
	for yLen != 0 {
		c.down(nil, 0)
		upLen = min(yLen, c.rSqueeze)
		c.up(y[start:upLen], 0)
		start += upLen
		yLen -= upLen
	}
	return y
}

func (c *Cyclist) down(x []byte, cd byte) {
	c.stateAddBytes(x)
	c.stateAddByte(1, len(x))
	if c.mode == Hash {
		cd &= 1
	}
	c.stateAddByte(cd, fB-1)
	c.phase = Down
}

func (c *Cyclist) up(y []byte, cu byte) {
	if c.mode != Hash {
		c.stateAddByte(cu, fB-1)
	}
	c.f()
	c.phase = Up
	// TODO(dadrian): Figure out how to do this without allocating memory
	c.stateCopyOut(y)
}

func (c *Cyclist) Absorb(x []byte) {
	c.absorbAny(x, c.rAbsorb, 0x03)
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
	return c.squeezeAny(length, 0x40)
}

func (c *Cyclist) SqueezeKey(length int) []byte {
	if c.mode != Key {
		panic("can't squeeze key in unkeyed mode")
	}
	return c.squeezeAny(length, 0x20)
}

func (c *Cyclist) Ratchet() {
	if c.mode != Key {
		panic("can't ratched key in unkeyed mode")
	}
	c.absorbAny(c.squeezeAny(lRatchet, 0x10), c.rAbsorb, 0)
}
