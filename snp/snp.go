package snp

// TODO(dadrian): Make this file only build on little-endian systems

// MinInt returns a if it is smaller than b. Otherwise, it returns b.
// TODO(dadrian): Enforce that this gets inlined?
func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// StateAddByte adds b to state at the given offset.
func StateAddByte(state *[25]uint64, b byte, offset int) {
	// TODO(dadrian): Implement
}

// StateAddBytes adds the first up to 200 bytes of b to state.
func StateAddBytes(state *[25]uint64, b []byte) {
	length := len(b)
	i := 0
	for stateIdx := 0; stateIdx < 25; stateIdx++ {
		// Little Endian
		for shift := 0; shift < 64; shift += 8 {
			state[stateIdx] ^= uint64(b[i]) << shift
			i++
			if i >= length {
				return
			}
		}
	}
}

func StateAddState(state *[25]uint64, b *[25]uint64) {
	for i := 0; i < 25; i++ {
		state[i] ^= b[i]
	}
}

// StateSetBytes sets state to the first up to 200 bytes of b.
func StateSetBytes(state *[25]uint64, b []byte) {
	length := len(b)
	i := 0
	for stateIdx := 0; stateIdx < 25; stateIdx++ {
		// Little Endian
		for shift := 0; shift < 64; shift += 8 {
			// Clear the byte, then XOR it in
			state[stateIdx] &= ^(uint64(0xFF) << shift)
			state[stateIdx] ^= uint64(b[i]) << shift
			i++
			if i >= length {
				return
			}
		}
	}
}

// StateExtractBytes copies the first len(dst) bytes of state into dst.
func StateExtractBytes(state *[25]uint64, dst []byte) {
	length := len(dst)
	i := 0
	for stateIdx := 0; stateIdx < 25; stateIdx++ {
		for shift := 0; shift < 64; shift += 8 {
			if i >= length {
				return
			}
			dst[i] = byte(state[stateIdx] >> shift)
			i++
		}
	}
}

func stateExtractAndAddStateLanes(state *[25]uint64, in *[25]uint64, out []byte, startLane, lanes int) {
	var sum uint64
	for i := 0; i < lanes; i++ {
		lane := startLane + i
		sum = state[lane] ^ in[lane]
		out[0] = byte(sum >> 56)
		out[1] = byte(sum >> 48)
		out[2] = byte(sum >> 40)
		out[3] = byte(sum >> 32)
		out[4] = byte(sum >> 24)
		out[5] = byte(sum >> 16)
		out[6] = byte(sum >> 8)
		out[7] = byte(sum)
		out = out[8:]
	}
}

func stateExtractAndAddStateInLane(state *[25]uint64, in *[25]uint64, lane int, offsetInLane int, out []byte, length int) {
	shift := 64
	shift -= 8 * offsetInLane
	for i := 0; i < length; i++ {
		shift -= 8
		out[i] = byte(in[lane]>>shift) ^ byte(state[lane]>>shift)
	}
}

// StateExtractAndAddStateToBytes extracts state, adds in b, and writes to out,
// starting at offset in both state and b.
func StateExtractAndAddStateToBytes(state *[25]uint64, in *[25]uint64, offset int, out []byte) {
	length := MinInt(len(out), 200-offset)
	// TODO(implement)
	if offset == 0 {
		stateExtractAndAddStateLanes(state, in, out, 0, length/8)
		stateExtractAndAddStateInLane(state, in, length/8, 0, out[8*(length/8):], length%8)
	} else {
		sizeLeft := length
		lane := offset / 8
		offsetInLane := offset % 8
		for {
			bytesInLane := MinInt(8-offsetInLane, sizeLeft)
			stateExtractAndAddStateInLane(state, in, lane, offsetInLane, out, bytesInLane)
			sizeLeft -= bytesInLane
			lane++
			offsetInLane = 0
			out = out[bytesInLane:]
			if sizeLeft == 0 {
				break
			}
		}
	}
}
