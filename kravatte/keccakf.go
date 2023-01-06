// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (!amd64 && !arm64) || purego || !gc

package kravatte

import "math/bits"

// rc stores the round constants for use in the ι step.
var rc = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

// keccakF1600 applies the Keccak permutation to a 1600b-wide
// state represented as a slice of 25 uint64s.
// TODO(baumanl): this doesn't pass kravatte tests because it needs to
// be modified to do 6 rounds instead of 24 I think
func keccakF1600(a *[25]uint64) {
	panic("keccak with 6 rounds is unimplemented in pure go")
}
