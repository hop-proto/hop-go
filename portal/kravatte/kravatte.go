package kravatte

import (
	"github.com/sirupsen/logrus"
	"zmap.io/portal/snp"
)

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

func rol64(a uint64, offset int) uint64 {
	return (a << offset) | (a >> (64 - offset))
}

func rollE(state *[25]uint64) {
	x0 := state[15]
	x1 := state[16]
	x2 := state[17]
	x3 := state[18]
	x4 := state[19]
	x5 := state[20]
	x6 := state[21]
	x7 := state[22]
	x8 := state[23]
	x9 := state[24]
	t := x0
	x0 = x1
	x1 = x2
	x2 = x3
	x3 = x4
	x4 = x5
	x5 = x6
	x6 = x7
	x7 = x8
	x8 = x9
	//x9 = ROL64(t, 7) ^ ROL64(x0, 18) ^ (x1 & (x0 >> 1));
	x9 = rol64(t, 7) ^ rol64(x0, 18) ^ (x1 & (x0 >> 1))

	state[15] = x0
	state[16] = x1
	state[17] = x2
	state[18] = x3
	state[19] = x4
	state[20] = x5
	state[21] = x6
	state[22] = x7
	state[23] = x8
	state[24] = x9
}

//func rollC(k *[200]byte) {
//	x00 := k[20*8+0]
//	x01 := k[20*8+1]
//	x02 := k[20*8+2]
//	x03 := k[20*8+3]
//	x04 := k[20*8+4]
//	x05 := k[20*8+5]
//	x06 := k[20*8+6]
//	x07 := k[20*8+7]
//
//	x10 := k[21*8+0]
//	x11 := k[21*8+1]
//	x12 := k[21*8+2]
//	x13 := k[21*8+3]
//	x14 := k[21*8+4]
//	x15 := k[21*8+5]
//	x16 := k[21*8+6]
//	x17 := k[21*8+7]
//
//	x20 := k[22*8+0]
//	x21 := k[22*8+1]
//	x22 := k[22*8+2]
//	x23 := k[22*8+3]
//	x24 := k[22*8+4]
//	x25 := k[22*8+5]
//	x26 := k[22*8+6]
//	x27 := k[22*8+7]
//
//	x30 := k[23*8+0]
//	x31 := k[23*8+1]
//	x32 := k[23*8+2]
//	x33 := k[23*8+3]
//	x34 := k[23*8+4]
//	x35 := k[23*8+5]
//	x36 := k[23*8+6]
//	x37 := k[23*8+7]
//
//	x40 := k[24*8+0]
//	x41 := k[24*8+1]
//	x42 := k[24*8+2]
//	x43 := k[24*8+3]
//	x44 := k[24*8+4]
//	x45 := k[24*8+5]
//	x46 := k[24*8+6]
//	x47 := k[24*8+7]
//
//	t0 := x00
//	t1 := x01
//	t2 := x02
//	t3 := x03
//	t4 := x04
//	t5 := x05
//	t6 := x06
//	t7 := x07
//
//	// Variables and roll
//	x0 = x1
//	x1 = x2
//	x2 = x3
//	x3 = x4
//	x4 = rol64(t, 7) ^ x0 ^ (x0 >> 3)
//
//	// Reassign back to k
//}

func rollC(state *[25]uint64) {
	x0 := state[20]
	x1 := state[21]
	x2 := state[22]
	x3 := state[23]
	x4 := state[24]
	t := x0

	x0 = x1
	x1 = x2
	x2 = x3
	x3 = x4
	x4 = rol64(t, 7) ^ x0 ^ (x0 >> 3)

	state[20] = x0
	state[21] = x1
	state[22] = x2
	state[23] = x3
	state[24] = x4
}

// Kravatte implements the Kravatte deck function, as defined in Section 7 of
// https://eprint.iacr.org/2016/1188.pdf. It is loosely based on the XKCP
// implementation of Kravatte by the Keccak Team.
type Kravatte struct {
	// TODO(dadrian): Some of these probably need to be uint64 arrays, since
	// Keccak operates on [25]uint64.
	// TODO(dadrian): Are these all the same size?
	k [25]uint64
	r [25]uint64
	x [widthBytes]byte
	y [widthBytes]byte
	q [widthBytes]byte

	queueOffset int
	phase       Phase
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

type keccakTest [25]uint64

// RefMaskInitialize closely follows the refernce implementation and
// specification of Kravatte, rather than th XKCP optimized implementation. It
// implements the first phase of Farfelle as defined in
// https://eprint.iacr.org/2016/1188.pdf.
//
// "First, the key derivation computes a b-bit mask k from the key K".
func (kv *Kravatte) RefMaskInitialize(key []byte) int {
	if len(key) >= widthBytes {
		return 1
	}
	key = Pad10NewSlice(key, widthBytes)
	snp.StateSetBytes(&kv.k, key)
	keccakF1600(&kv.k)
	kv.r = kv.k
	kv.x = zero
	kv.phase = PhaseCompressing
	kv.queueOffset = 0
	return 0
}

// KraRef implements the input compression phase
func (kv *Kravatte) KraRef(in []byte) int {
	return 1
}

// Pad10NewSlice implements the Pad10 function for a byte slice and given block
// size length (in bytes). It returns a newly allocated slice.
func Pad10NewSlice(in []byte, blockByteLen int) []byte {
	blocks := len(in) / blockByteLen
	paddingBytes := len(in) % blockByteLen
	if paddingBytes > 0 {
		blocks++
	}
	byteLen := blocks * blockByteLen
	out := make([]byte, byteLen)
	n := copy(out, in)
	out[n] = 1
	return out
}

func (kv *Kravatte) compress(message []byte, lastFlag int) int {
	messageLen := len(message)
	remainingLen := len(message)
	if remainingLen >= widthBytes {
		var state [25]uint64
		for {
			state = kv.k
			rollC(&kv.r)
			snp.StateAddBytes(&state, message[:widthBytes])
			keccakF1600(&state)
			snp.StateExtractAndAddBytes(&state, kv.x[:], kv.x[:])
			message = message[widthBytes:]
			remainingLen -= widthBytes
			if remainingLen < widthBytes {
				break
			}
		}
	}
	if lastFlag != 0 {
		var state [25]uint64
		state = kv.k
		rollC(&kv.r)
		snp.StateAddBytes(&state, message)
		snp.StateAddByte(&state, 1, remainingLen)
		keccakF1600(&state)
		snp.StateExtractAndAddBytes(&state, kv.x[:], kv.x[:])
		rollC(&kv.r)
		return messageLen
	}
	return messageLen - remainingLen
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
	inputLen := len(in)
	finalFlag := flags & FlagLastPart
	if (flags & FlagInit) != 0 {
		// Do init
		kv.r = kv.k
		kv.x = zero
		kv.queueOffset = 0
	}
	if kv.phase != PhaseCompressing {
		kv.phase = PhaseCompressing
		kv.queueOffset = 0
	} else if kv.queueOffset != 0 {
		// Data is already queued
		toQueueLen := min(inputLen, widthBytes-kv.queueOffset)
		copy(kv.q[kv.queueOffset:], in[:toQueueLen])
		in = in[:toQueueLen]
		inputLen -= toQueueLen
		kv.queueOffset += inputLen
		if kv.queueOffset == widthBytes {
			// Queue is full
			kv.compress(kv.q[:kv.queueOffset], 0)
			kv.queueOffset = 0
		} else if finalFlag != 0 {
			kv.compress(kv.q[:kv.queueOffset], 1)
			kv.queueOffset = 0
			return 0
		}
	}
	if (inputLen >= widthBytes) || (finalFlag != 0) {
		// Compress blocks
		n := kv.compress(in, finalFlag)
		in = in[n:]
		inputLen -= n
	}
	if inputLen != 0 {
		// Queue eventual residual message bytes
		copy(kv.q[:], in[:inputLen])
		kv.queueOffset = inputLen
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
		if kv.queueOffset != 0 {
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
	if kv.queueOffset != 0 {
		// Data is already queued
		bitLen := min(outputBitLen, widthBits-kv.queueOffset)
		byteLen := (bitLen + 7) / 8
		outputEnd := outputOffset + byteLen
		queueOffsetBytes := kv.queueOffset / 8
		queueEnd := queueOffsetBytes + byteLen
		copy(out[outputOffset:outputEnd], kv.q[queueOffsetBytes:queueEnd])
		kv.queueOffset += bitLen
		if kv.queueOffset == widthBits {
			kv.queueOffset = 0
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
			kv.queueOffset = 8 * offset
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
