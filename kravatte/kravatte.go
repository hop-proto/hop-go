package kravatte

import (
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
	widthBits  = 8 * widthBytes
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
	k  [25]uint64
	kr [25]uint64
	x  [25]uint64
	y  [25]uint64
	q  [widthBytes]byte

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

var zero [25]uint64

// RefMaskInitialize roughtly follows MaskDerivation from XKCP. It is used to
// initialize a Kravatte instance.
func (kv *Kravatte) RefMaskInitialize(key []byte) int {
	if len(key) >= widthBytes {
		return 1
	}
	kv.k = zero
	snp.StateSetBytes(&kv.k, key)
	snp.StateSetByte(&kv.k, 1, len(key))
	keccakF1600(&kv.k)
	kv.kr = kv.k
	kv.x = zero
	kv.phase = PhaseCompressing
	kv.queueOffsetBits = 0
	return 0
}

func (kv *Kravatte) compress(message []byte, messageBitLen *int, lastFlag int) int {
	messageByteLen := *messageBitLen / 8 // do not include partial last byte
	bytesCompressed := 0
	if messageByteLen >= widthBytes {
		for {
			state := kv.kr
			rollC(&kv.kr)
			snp.StateAddBytes(&state, message[:widthBytes])
			keccakF1600(&state)
			snp.StateAddState(&kv.x, &state) // Add state to x, not vice-versa
			message = message[widthBytes:]
			bytesCompressed += widthBytes
			messageByteLen -= widthBytes
			if messageByteLen < widthBytes {
				break
			}
		}
	}
	*messageBitLen %= widthBits
	if lastFlag != 0 {
		state := kv.kr
		rollC(&kv.kr)
		snp.StateAddBytes(&state, message[:messageByteLen])
		message = message[messageByteLen:]
		bytesCompressed += messageByteLen
		*messageBitLen %= 8
		if *messageBitLen != 0 {
			snp.StateAddByte(&state, message[0]|(1<<*messageBitLen), messageByteLen)
			bytesCompressed += 1
		} else {
			snp.StateAddByte(&state, 1, messageByteLen)
		}
		keccakF1600(&state)
		snp.StateAddState(&kv.x, &state) // Add state to x, not vice-versa
		rollC(&kv.kr)
		*messageBitLen = 0
	}
	return bytesCompressed
}

// Kra compresses input into the sponge.
func (kv *Kravatte) Kra(in []byte, inputBitLen int, flags int) int {
	finalFlag := flags & FlagLastPart
	if finalFlag == 0 && (inputBitLen&7) != 0 {
		return 1
	}
	if (flags & FlagInit) != 0 {
		// Do init
		kv.kr = kv.k
		kv.x = zero
		kv.queueOffsetBits = 0
	}
	if kv.phase != PhaseCompressing {
		kv.phase = PhaseCompressing
		kv.queueOffsetBits = 0
	} else if kv.queueOffsetBits != 0 {
		// Data is already queued
		bitLen := min(inputBitLen, widthBits-kv.queueOffsetBits)
		byteLen := (bitLen + 7) / 8
		copy(kv.q[kv.queueOffsetBits/8:], in[:byteLen])
		in = in[byteLen:]
		inputBitLen -= bitLen
		kv.queueOffsetBits += bitLen
		if kv.queueOffsetBits == widthBits {
			// Queue is full
			kv.compress(kv.q[:], &kv.queueOffsetBits, 0)
			kv.queueOffsetBits = 0
		} else if finalFlag != 0 {
			kv.compress(kv.q[:], &kv.queueOffsetBits, 1)
			return 0
		}
	}
	if (inputBitLen >= widthBytes) || (finalFlag != 0) {
		// Compress blocks
		n := kv.compress(in, &inputBitLen, finalFlag)
		in = in[n:]
	}
	if inputBitLen != 0 {
		// Queue eventual residual message bytes
		copy(kv.q[:], in[:inputBitLen/8])
		kv.queueOffsetBits = inputBitLen
	}
	return 0
}

// Vatte squeezes the sponge into the output.
func (kv *Kravatte) Vatte(out []byte, outBits int, flags int) int {
	finalFlag := flags & FlagLastPart
	if finalFlag == 0 && (outBits&7) != 0 {
		return 1
	}
	if kv.phase == PhaseCompressing {
		if kv.queueOffsetBits != 0 {
			return 1
		}
		if (flags & FlagShort) != 0 {
			kv.y = kv.x
		} else {
			state := kv.x
			keccakF1600(&state)
			kv.y = state
		}
		kv.phase = PhaseExpanding
	} else if kv.phase != PhaseExpanding {
		return 1
	}
	if kv.queueOffsetBits != 0 {
		// Data is already queued
		toOutputBitLen := min(outBits, widthBits-kv.queueOffsetBits)
		toOutputByteLen := (toOutputBitLen + 7) / 8
		q := kv.q[kv.queueOffsetBits/8:]
		copy(out, q[:toOutputByteLen])
		kv.queueOffsetBits += toOutputBitLen
		if kv.queueOffsetBits == widthBits {
			kv.queueOffsetBits = 0
		}
		outBits -= toOutputBitLen
		if (finalFlag != 0) && (outBits == 0) {
			toOutputBitLen &= 7
			if toOutputBitLen != 0 {
				// cleanup last incomplete byte
				out[toOutputByteLen-1] &= (1 << toOutputBitLen) - 1
			}
			kv.phase = PhaseExpanded
			return 0
		}
		out = out[toOutputByteLen:]
	}

	remainingByteLen := (outBits + 7) / 8
	var previousBlock []byte
	var previousBlockLen int
	if remainingByteLen != 0 {
		var state [25]uint64
		var byteLen int
		for {
			byteLen = min(remainingByteLen, widthBytes)
			state = kv.y
			rollE(&kv.y)
			keccakF1600(&state)
			snp.StateExtractAndAddStateToBytes(&state, &kv.kr, 0, out[:byteLen])
			previousBlock = out
			previousBlockLen = byteLen
			out = out[byteLen:]
			remainingByteLen -= byteLen
			if remainingByteLen == 0 {
				break
			}
		}
		if (finalFlag == 0) && (byteLen != widthBytes) {
			// Put the rest of the expanded data in the queue
			offset := byteLen
			byteLen = widthBytes - byteLen
			q := kv.q[offset:]
			snp.StateExtractAndAddStateToBytes(&state, &kv.kr, offset, q[:byteLen])
			kv.queueOffsetBits = offset * 8
		}
	}
	if finalFlag != 0 {
		outBits &= 7
		if outBits != 0 {
			// Cleanup last incomplete byte
			previousBlock[previousBlockLen-1] &= (1 << outBits) - 1
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
	if kv.Kra(in, len(in)*8, flags) != 0 {
		return 1
	}
	return kv.Vatte(out, len(out)*8, flags)
}
