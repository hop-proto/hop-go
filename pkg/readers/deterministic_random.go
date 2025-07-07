package readers

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"

	"hop.computer/hop/pkg"
	"hop.computer/hop/pkg/must"
)

var iv = [aes.BlockSize]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
var mask = [aes.BlockSize]byte{0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77}

type ctrReader struct {
	stream cipher.Stream
}

// Read implements io.Reader. It will return a deterministic byte sequence based
// on the seed and the total number of bytes read. The number of calls does not
// matter. It cannot fail.
func (c *ctrReader) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i += len(mask) {
		chunk := p[i:]
		c.stream.XORKeyStream(chunk, mask[0:min(len(chunk), len(mask))])
	}
	return len(p), nil
}

var _ io.Reader = &ctrReader{}

// DeterministicRandomReader returns a "random" reader based on the seed
// provided, using AES in CTR mode. The key is based on the seed. The IV is
// static. The output data is the key stream XOR'd with a static mask of 0x77
// for each byte.
func DeterministicRandomReader(seed uint64) io.Reader {
	key := [16]byte{}
	binary.LittleEndian.PutUint64(key[:], seed)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		pkg.Panicf("unable to create new aes: %s", err)
	}
	ctr := cipher.NewCTR(block, iv[:])
	return &ctrReader{
		stream: ctr,
	}
}

type DeterministicCoinFlipper struct {
	r    *ctrReader
	bits int
}

// Flip flips the (biased) coin. True represents heads.
func (f *DeterministicCoinFlipper) Flip() bool {
	var buf [1]byte
	_ = must.Do(f.r.Read(buf[:]))

	// Extract the lowest n bits
	mask := byte((1 << f.bits) - 1)
	result := buf[0] & mask

	// Only the all-zero case is true (i.e. 00000000 up to n bits)
	return result == 0
}

func NewDeterministicCoinFlipper(seed uint64, bits int) *DeterministicCoinFlipper {
	if bits > 7 || bits < 0 {
		pkg.Panicf("bits must be in the range 0-7, got %d", bits)
	}
	r := DeterministicRandomReader(seed).(*ctrReader)
	return &DeterministicCoinFlipper{
		r:    r,
		bits: bits,
	}

}
