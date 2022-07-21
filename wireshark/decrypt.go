package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"fmt"

	"hop.computer/hop/kravatte"
	"hop.computer/hop/transport"
)

//export KeyLen
const KeyLen = transport.KeyLen

//export PlaintextLen
func PlaintextLen(transportLen int) int {
	return transport.PlaintextLen(transportLen)
}

// Convert key of the form [num num num num] to the corresponding binary string
// Returns nil on invalid parse
//export parseKey
func parseKey(keyString unsafe.Pointer, keyLen C.size_t) (unsafe.Pointer, int) {
	key := string(unsafe.Slice((*byte)(keyString), keyLen))
	var res []byte
	_, err := fmt.Sscanf(key, "%x", &res)
	if err != nil {
		return nil, 0
	}
	return C.CBytes(res), len(res)
}

//export freeKey
func freeKey(key unsafe.Pointer) {
	C.free(key)
}

const ErrKeyLen = 1
const ErrBufOverflow = 2
const ErrUnexpectedMessage = 3
const ErrInvalidMessage = 4
const ErrKravatte = 5
const ErrPacketExtraData = 6
const ErrAeadOpen = 7
const ErrPlaintextSize = 8

// This is a lightly modified version of (*SessionState).ReadPacket to provide a better FFI

// Returns number of bytes read, error
//export readPacket
func readPacket(
	plaintext_buf unsafe.Pointer, plaintext_len C.int,
	pkt_buf unsafe.Pointer, pkt_len C.int,
	key_buf unsafe.Pointer, key_len C.int,
) (int, int) {
	if key_len != KeyLen {
		fmt.Printf("%v %v\n", key_len, KeyLen)
		return 0, ErrKeyLen
	}
	key := unsafe.Slice((*byte)(key_buf), KeyLen)
	plaintext := unsafe.Slice((*byte)(plaintext_buf), plaintext_len)
	pkt := unsafe.Slice((*byte)(pkt_buf), pkt_len)
	plaintextLen := transport.PlaintextLen(len(pkt))
	ciphertextLen := plaintextLen + transport.TagLen
	if plaintextLen > len(plaintext) {
		return 0, ErrBufOverflow
	}

	// Header
	b := pkt
	if mt := transport.MessageType(b[0]); mt != transport.MessageTypeTransport {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return 0, ErrInvalidMessage
	}
	b = b[transport.HeaderLen:]

	// SessionID
	/*
		if !bytes.Equal(ss.sessionID[:], b[:SessionIDLen]) {
			return 0, ErrUnknownSession
		}
	*/
	b = b[transport.SessionIDLen:]

	b = b[transport.CounterLen:]

	aead, err := kravatte.NewSANSE(key[:])
	if err != nil {
		return 0, ErrKravatte
	}
	enc := b[:ciphertextLen]
	b = b[ciphertextLen:]
	if len(b) != 0 {
		return 0, ErrPacketExtraData
	}
	out, err := aead.Open(plaintext[:0], nil, enc, pkt[:transport.AssociatedDataLen])
	if err != nil {
		return 0, ErrAeadOpen
	}
	if len(out) != plaintextLen {
		return 0, ErrPlaintextSize
	}

	return plaintextLen, 0
}

// We need an empty main function so that the library compiles
func main() {}
