package kravatte

const (
	// FlagNone is the zero value and indicates no flags are set.
	FlagNone = 0

	// FlagInit initializes a new session
	FlagInit = 1

	// FlagLastPart indicates the last part of an input or output.
	FlagLastPart = 2 // Indicates the last part of input/output

	// FlagShort indicates that the call should use Short-Kravatte.
	FlagShort = 4
)

// Kravatte implements the Kravatte deck function, as defined in Section 7 of
// https://eprint.iacr.org/2016/1188.pdf. It is loosely based on the XKCP
// implementation of Kravatte by the Keccak Team.
type Kravatte struct {
	// TODO(dadrian)
}

func (k *Kravatte) kra(in []byte, flags int) int {
	return 1
}

func (k *Kravatte) vatte(out []byte, flags int) int {
	return 1
}

// Kravatte function to compress input data and expand output data. Flags is a
// bitwise combination of KRAVATTE_FLAG_NONE, KRAVATTE_FLAG_INIT,
// KRAVATTE_FLAG_SHORT, and KRAVATTE_FLAG_LAST_PART. KRAVATTE_FLAG_LAST_PART is
// internally forced to true for input and output.
func (k *Kravatte) Kravatte(in []byte, out []byte, flags int) int {
	flags |= FlagLastPart
	if k.kra(in, flags) != 0 {
		return 1
	}
	return k.vatte(out, flags)
}
