// Package cyclist contains an implementtation of the Cyclist duplex function
// instantiated with 12 rounds of Keccak-p[1600]. It is directly ported from the
// XKCP implementation. This package is experimental and unoptimized.
package cyclist

// Phase is a enum used to represent internal state of Cyclist
type Phase int

// Cyclist has two phases: Up and Down. These are used internally by the
// permutation.
const (
	Up Phase = iota
	Down
)

// Mode is either Hash or Key
type Mode int

// Known values of Mode
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
// object as defined in https://eprint.iacr.org/2018/767.pdf. It is instantiated
// with 12-rounds of Keccak-p[1600] as the permutation.
//
// It uses a 1088-bit rKin and rKout, a 256-bit ratchet, a 1088-bit rHash, and a
// 1600-bit permutation. For details, see
// https://github.com/XKCP/XKCP/pull/75#issuecomment-718093434.
//
// Functions that are limited to Key or Hash mode will panic if called on an
// object in the wrong mode. There are no error values returned.
type Cyclist struct {
	phase             Phase
	mode              Mode
	rAbsorb, rSqueeze int
	s                 [25]uint64
}

// InitializeEmpty resets a Cyclist object to the empty state in Hash mode.
func (c *Cyclist) InitializeEmpty() {
	c.phase = Up
	c.mode = Hash
	c.rAbsorb = rHash
	c.rSqueeze = rHash
	for i := 0; i < len(c.s); i++ {
		c.s[i] = 0
	}
}

// Initialize resets a Cyclist object to an initial state, with an optional key
func (c *Cyclist) Initialize(key, id, counter []byte) {
	c.phase = Up
	c.mode = Hash
	c.rAbsorb = rHash
	c.rSqueeze = rHash
	for i := 0; i < len(c.s); i++ {
		c.s[i] = 0
	}
	if len(key) > 0 {
		c.absorbKey(key, id, counter)
	}
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func (c *Cyclist) stateAddByte(b byte, offset int) {
	idx := offset / 8
	byteIdx := offset % 8
	shift := byteIdx * 8
	x := uint64(b) << shift
	c.s[idx] ^= x
}

func (c *Cyclist) stateAddBytes(b []byte) {
	length := len(b)
	if length == 0 {
		return
	}
	i := 0
	for stateIdx := 0; stateIdx < 25; stateIdx++ {
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

// stateCopyAndAddBytes adds the first len(in) bytes of the state to in, and
// writes into out.
func (c *Cyclist) stateCopyAndAddBytes(in, out []byte) {
	length := len(in)
	i := 0
	for stateIdx := 0; stateIdx < 25; stateIdx++ {
		for shift := 0; shift < 64; shift += 8 {
			if i >= length {
				return
			}
			out[i] = byte(c.s[stateIdx] >> shift)
			out[i] ^= in[i]
			i++
		}
	}
}

func (c *Cyclist) f() {
	keccakF1600(&c.s)
	// When debugging against the C implementation, uncomment the following
	// code. Note that if you print c.s directly on a little endian system, you
	// will have to read the hex bytes "backwords" in each uint64 to compare to
	// the bytestream, stateCopyOut is called in order to avoid this.
	// dbg := make([]byte, 200)
	// c.stateCopyOut(dbg)
	// fmt.Fprintf(os.Stderr, "After f(): % x\n", dbg)
}

func (c *Cyclist) absorbAny(x []byte, r int, cd byte) {
	xLen := len(x)
	start := 0
	for {
		if c.phase != Up {
			c.up(nil, 0x00)
		}
		splitLen := min(xLen, r)
		c.down(x[start:start+splitLen], cd)
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
	copy(kid[0:], key)
	copy(kid[klen:], id)
	kid[klen+idlen] = byte(idlen)
	c.absorbAny(kid[0:klen+idlen+1], c.rAbsorb, 0x02)
	if len(counter) > 0 {
		c.absorbAny(counter, 1, 0x00)
	}
}

func (c *Cyclist) crypt(out, in []byte, decrypt bool) {
	// TODO(dadrian): Pass this in so that memory allocation isn't necessary
	var p [rKout]byte
	cu := byte(0x80)
	ioLen := len(in)
	start := 0
	for {
		splitLen := min(ioLen, rKout)
		end := start + splitLen
		if decrypt {
			c.up(nil, cu)
			c.stateCopyAndAddBytes(in[start:end], out[start:])
			c.down(out[start:end], 0x00)
		} else {
			copy(p[:], in[start:end])
			c.up(nil, cu)
			c.stateCopyAndAddBytes(in[start:end], out[start:])
			c.down(p[0:splitLen], 0x00)
		}
		start += splitLen
		ioLen -= splitLen

		cu = 0x00
		if ioLen == 0 {
			break
		}
	}
}

func (c *Cyclist) squeezeAny(y []byte, cu byte) {
	yLen := len(y)
	upLen := min(yLen, c.rSqueeze)
	c.up(y[0:upLen], cu)
	start := upLen
	yLen -= upLen
	for yLen != 0 {
		c.down(nil, 0)
		upLen = min(yLen, c.rSqueeze)
		c.up(y[start:start+upLen], 0x00)
		start += upLen
		yLen -= upLen
	}
}

func (c *Cyclist) down(x []byte, cd byte) {
	c.stateAddBytes(x)
	c.stateAddByte(0x01, len(x))
	if c.mode == Hash {
		cd &= 0x01
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
	c.stateCopyOut(y)
}

// Absorb absorbs the entirety of x.
func (c *Cyclist) Absorb(x []byte) {
	c.absorbAny(x, c.rAbsorb, 0x03)
}

// Encrypt encrypts plaintext and writes to ciphertext. The output will be the
// same length as the input. The ciphertext slice must already be allocated.
func (c *Cyclist) Encrypt(ciphertext, plaintext []byte) {
	// TODO(dadrian): Is this the correct order for input/output arguments?
	if c.mode != Key {
		panic("can't encrypt in unkeyed mode")
	}
	c.crypt(ciphertext, plaintext, false)
}

// Decrypt decrypts ciphertext to plaintext. The plaintext will have the same
// length as the ciphertext. The plaintext slice must already be allocated.
// There is no authenticity tag checked. If the encryption operation needs
// integrity, generate a MAC using Squeeze, and compare the outputs before
// operating on the decrypted data.
func (c *Cyclist) Decrypt(plaintext, ciphertext []byte) {
	if c.mode != Key {
		panic("can't decrypt in unkeyed mode")
	}
	c.crypt(plaintext, ciphertext, true)
}

// Squeeze outputs len(y) bytes. It can be used as an authenticity tag.
func (c *Cyclist) Squeeze(y []byte) {
	c.squeezeAny(y, 0x40)
}

// SqueezeKey squeezes out len(y) bytes to be used as a new key when in keyed
// mode.
func (c *Cyclist) SqueezeKey(y []byte) {
	if c.mode != Key {
		panic("can't squeeze key in unkeyed mode")
	}
	c.squeezeAny(y, 0x20)
}

// Ratchet clears 256-bits of internal state. It can only be called in keyed
// mode.
func (c *Cyclist) Ratchet() {
	if c.mode != Key {
		panic("can't ratched key in unkeyed mode")
	}
	var y [lRatchet]byte
	c.squeezeAny(y[:], 0x10)
	c.absorbAny(y[:], c.rAbsorb, 0x00)
}

// NewCyclist returns an initialized and empty Cyclist object
func NewCyclist() *Cyclist {
	c := new(Cyclist)
	c.InitializeEmpty()
	return c
}
