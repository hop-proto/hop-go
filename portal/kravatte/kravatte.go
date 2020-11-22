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

const (
	widthBytes = 200
	widthBits  = 1600
)

// Kravatte implements the Kravatte deck function, as defined in Section 7 of
// https://eprint.iacr.org/2016/1188.pdf. It is loosely based on the XKCP
// implementation of Kravatte by the Keccak Team.
type Kravatte struct {
	// TODO(dadrian): Some of these probably need to be uint64 arrays, since
	// Keccak operates on [25]uint64.
	k [widthBytes]byte
	r [widthBytes]byte
	x [widthBytes]byte
	y [widthBytes]byte
	q [widthBytes]byte

	queueOffsetBits int
	phase           Phase
}

// Phase represents a Kravatte phase.
type Phase int

// Phases of Kravatte
const (
	PhaseCompressing Phase = iota
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var zero [widthBytes]byte

func (kv *Kravatte) compress(lastFlag int) int {
	return 0
}

func (kv *Kravatte) kra(in []byte, flags int) int {
	finalFlag := flags & FlagLastPart
	inputBitLen := 8 * len(in)
	if (finalFlag == 0) && ((inputBitLen & 7) != 0) {
		return 1
	}
	if (flags & FlagInit) != 0 {
		// Do init
		copy(kv.r[:], kv.k[:])
		copy(kv.x[:], zero[:])
		kv.queueOffsetBits = 0
	}
	inputByteOffset := 0
	if kv.phase != PhaseCompressing {
		kv.phase = PhaseCompressing
		kv.queueOffsetBits = 0
	} else if kv.queueOffsetBits != 0 {
		// Data is already queued
		bitLen := min(inputBitLen, widthBits-kv.queueOffsetBits)
		byteLen := (bitLen + 7) / 8
		queueOffsetBytes := kv.queueOffsetBits / 8

		copy(kv.q[queueOffsetBytes:], in[inputByteOffset:])
		inputByteOffset += byteLen
		inputBitLen -= bitLen
		kv.queueOffsetBits += bitLen
		if kv.queueOffsetBits == widthBits {
			// Queue is full
			kv.compress(0)
			kv.queueOffsetBits = 0
		} else if finalFlag != 0 {
			kv.compress(1)
			return 0
		}
	}
	if (inputBitLen >= widthBits) || (finalFlag != 0) {
		// Compress blocks
		n := kv.compress(finalFlag)
		inputByteOffset += n
		inputBitLen -= 8 * n
	}
	if inputBitLen != 0 {
		// Queue eventual residual message bytes
		end := inputByteOffset + inputBitLen/8
		copy(kv.q[:], in[inputByteOffset:end])
		kv.queueOffsetBits = inputBitLen
	}
	return 0
}

func (kv *Kravatte) vatte(out []byte, flags int) int {
	return 1
}

// Kravatte function to compress input data and expand output data. Flags is a
// bitwise combination of KRAVATTE_FLAG_NONE, KRAVATTE_FLAG_INIT,
// KRAVATTE_FLAG_SHORT, and KRAVATTE_FLAG_LAST_PART. KRAVATTE_FLAG_LAST_PART is
// internally forced to true for input and output.
func (kv *Kravatte) Kravatte(in []byte, out []byte, flags int) int {
	flags |= FlagLastPart
	if kv.kra(in, flags) != 0 {
		return 1
	}
	return kv.vatte(out, flags)
}
