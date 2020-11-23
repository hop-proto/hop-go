package kravatte

import "github.com/sirupsen/logrus"

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
	// TODO(dadrian): Confirm these values
	rollWidthBytes = 200
	rollWidthBites = 1600
)

// Kravatte implements the Kravatte deck function, as defined in Section 7 of
// https://eprint.iacr.org/2016/1188.pdf. It is loosely based on the XKCP
// implementation of Kravatte by the Keccak Team.
type Kravatte struct {
	// TODO(dadrian): Some of these probably need to be uint64 arrays, since
	// Keccak operates on [25]uint64.
	// TODO(dadrian): Are these all the same size?
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
	PhaseExpanding
	PhaseExpanded
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

// TODO(dadrian): Implement
func copyBytesToUint64(dst []uint64, src []byte) int {
	return len(src)
}

// TODO(dadrian): Implement
func copyUint64ToBytes(dst []byte, src []uint64) int {
	return len(src) / 8
}

func (kv *Kravatte) rollE(encbuf []byte, flags int) int {
	// Implement
	return 1
}

func (kv *Kravatte) rollC() int {
	// Implement
	return 1
}

// Kra compresses input into the sponge.
func (kv *Kravatte) Kra(in []byte, flags int) int {
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

// Vatte squeezes the sponge into the output.
func (kv *Kravatte) Vatte(out []byte, flags int) int {
	var encbuf [rollWidthBytes]byte
	outputByteLen := len(out)
	outputBitLen := 8 * outputByteLen
	outputOffset := 0
	finalFlag := flags & FlagLastPart
	if (finalFlag == 0) && (outputBitLen&7 != 0) {
		return 1
	}
	if kv.phase == PhaseCompressing {
		if kv.queueOffsetBits != 0 {
			return 1
		}
		if (flags & FlagShort) != 0 {
			copy(kv.y[:], kv.x[:])
		} else {
			var state [25]uint64
			// mInit(state)?
			copyBytesToUint64(state[:], kv.x[:])
			keccakF1600(&state)
			copyUint64ToBytes(kv.y[:], state[:])
		}
		kv.phase = PhaseExpanding
		// TODO(dadrian): Remove debug logs
		logrus.Debugf("y: %x", kv.y[:])
		logrus.Debugf("k: %x", kv.k[:])
	} else if kv.phase != PhaseExpanding {
		// TODO(dadrian): Should this be a switch?
		return 1
	}
	if kv.queueOffsetBits != 0 {
		// Data is already queued
		bitLen := min(outputBitLen, widthBits-kv.queueOffsetBits)
		byteLen := (bitLen + 7) / 8
		outputEnd := outputOffset + byteLen
		queueOffsetBytes := kv.queueOffsetBits / 8
		queueEnd := queueOffsetBytes + byteLen
		copy(out[outputOffset:outputEnd], kv.q[queueOffsetBytes:queueEnd])
		kv.queueOffsetBits += bitLen
		if kv.queueOffsetBits == widthBits {
			kv.queueOffsetBits = 0
		}
		outputOffset += byteLen
		outputBitLen -= bitLen
		if (finalFlag != 0) && (outputBitLen == 0) {
			bitLen &= 7
			if bitLen != 0 {
				// cleanup last incomplete byte
				out[outputOffset-1] &= (1 << bitLen) - 1
			}
			kv.phase = PhaseExpanded
			return 0
		}
	}
	// WHAT HAPPENS HERE? Somehow Roll functions are called?
	/*
	   outputByteLen = (outputBitLen + 7) / 8;
	   #if defined(KeccakP1600times8_implementation) && !defined(KeccakP1600times8_isFallback)
	   #if defined(KeccakF1600times8_FastKravatte_supported)
	   ParallelExpandLoopFast( 8 )
	   #else
	   ParallelExpandLoopPlSnP( 8 )
	   #endif
	   #endif
	   #if defined(KeccakP1600times4_implementation) && !defined(KeccakP1600times4_isFallback)
	   #if defined(KeccakF1600times4_FastKravatte_supported)
	   ParallelExpandLoopFast( 4 )
	   #else
	   ParallelExpandLoopPlSnP( 4 )
	   #endif
	   #endif
	   #if defined(KeccakP1600times2_implementation) && !defined(KeccakP1600times2_isFallback)
	   #if defined(KeccakF1600times2_FastKravatte_supported)
	   ParallelExpandLoopFast( 2 )
	   #else
	   ParallelExpandLoopPlSnP( 2 )
	   #endif
	   #endif
	*/
	if outputByteLen != 0 {
		var state [25]uint64
		var byteLen int
		// mInit(state)?
		for {
			byteLen = min(outputByteLen, widthBytes)
			end := outputOffset + byteLen
			copyBytesToUint64(state[:], kv.y[:])
			kv.rollE(encbuf[:], 1)
			keccakF1600(&state)
			// TODO(dadrian): This is actually an extract and add
			copyUint64ToBytes(out[outputOffset:end], state[:])
			logrus.Debugf("out 1: %x", out[outputOffset:end])
			outputOffset += byteLen
			outputByteLen -= byteLen
			if outputByteLen == 0 {
				break
			}
		}
		if finalFlag != 0 && (byteLen != widthBytes) {
			// Put the rest of the expanded data in the queue
			offset := byteLen
			byteLen = widthBytes - byteLen
			end := offset + byteLen
			// TODO(dadrian): Needs to do an add of roll
			copyUint64ToBytes(kv.q[offset:end], state[offset:end])
			kv.queueOffsetBits = 8 * offset
		}
	}
	if finalFlag != 0 {
		outputBitLen &= 7
		if outputBitLen != 0 {
			// cleanup incomplete byte
			out[outputOffset-1] &= (1 << outputBitLen) - 1
			logrus.Debugf("out L: %x", out[outputOffset-1])
		}
		kv.phase = PhaseExpanded
	}
	return 0
}

// Kravatte function to compress input data and expand output data. Flags is a
// bitwise combination of KRAVATTE_FLAG_NONE, KRAVATTE_FLAG_INIT,
// KRAVATTE_FLAG_SHORT, and KRAVATTE_FLAG_LAST_PART. KRAVATTE_FLAG_LAST_PART is
// internally forced to true for input and output.
func (kv *Kravatte) Kravatte(in []byte, out []byte, flags int) int {
	flags |= FlagLastPart
	if kv.Kra(in, flags) != 0 {
		return 1
	}
	return kv.Vatte(out, flags)
}
