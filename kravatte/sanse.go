package kravatte

import (
	"crypto/cipher"
	"crypto/subtle"
)

const (
	KravatteSANSETagSize = 32
)

type sanse struct {
	kravatte Kravatte
	e        uint32
}

var _ cipher.AEAD = &sanse{}

func (s *sanse) NonceSize() int {
	return 0
}

func (s *sanse) Overhead() int {
	return KravatteSANSETagSize
}

func (s *sanse) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	// This has a specific slice behavior that we need to match, look at what GCM does.
	panic("implement me")
}

func (s *sanse) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	panic("implement me")
}

func NewSANSE(key []byte) cipher.AEAD {
	s := &sanse{
		kravatte: Kravatte{},
		e:        0,
	}
	if s.kravatte.RefMaskInitialize(key) != 0 {
		panic("unable to initialize kravatte")
	}
	return s
}

func memxoris(target, source []byte, bitLen int) {
	byteLen := bitLen / 8
	for i := 0; i < byteLen; i++ {
		target[i] ^= source[i]
	}
	bitLen &= 7
	if bitLen != 0 {
		target[byteLen] ^= source[byteLen]
		target[byteLen] &= (1 << bitLen) - 1
	}
}

func (s *sanse) addToHistory(data []byte, dataBitLen int, appendix byte, appendixLen int) int {
	var lastByte [1]byte
	if s.kravatte.Kra(data, dataBitLen & ^7, FlagNone) != 0 {
		return 1
	}
	data = data[dataBitLen>>3:]
	dataBitLen &= 7
	if dataBitLen == 0 {
		lastByte[0] = appendix | byte(s.e<<appendixLen)
		dataBitLen = appendixLen + 1
	} else if dataBitLen <= (8 - (appendixLen + 1)) {
		lastByte[0] = (data[0] & byte((1<<dataBitLen)-1)) | (appendix << dataBitLen) | byte(s.e<<(dataBitLen+appendixLen))
		dataBitLen += appendixLen + 1
	} else {
		// dataBitLen too big to hold everything in last byte
		bitsLeft := 8 - dataBitLen
		lastByte[0] = (data[0] & byte((1<<dataBitLen)-1)) | ((appendix & byte((1<<bitsLeft)-1)) << dataBitLen)
		appendixLen -= bitsLeft
		appendix >>= bitsLeft
		if s.kravatte.Kra(lastByte[:], 8, FlagNone) != 0 {
			return 1
		}
		lastByte[0] = (appendix | byte(s.e<<appendixLen))
		dataBitLen = appendixLen + 1
	}
	return s.kravatte.Kra(lastByte[:], dataBitLen, FlagLastPart)
}

// wrap assumes all of these buffers have been preallocated to the correct length
func (s *sanse) wrap(plaintext []byte, ciphertext []byte, dataBitLen int, ad []byte, adBitLen int, tag []byte) int {
	// if |A| > 0 OR |P| = 0 then
	if adBitLen != 0 || dataBitLen == 0 {
		// history <- A || 0 || e . history
		if s.addToHistory(ad, adBitLen, 0, 1) != 0 {
			return 1
		}
	}
	// if |P| > 0 then
	if dataBitLen != 0 {
		initalHistory := s.kravatte // needs to be a copy

		// T = 0t + FK (P || 01 || e . history)
		if s.addToHistory(plaintext, dataBitLen, 2, 2) != 0 {
			return 1
		}
		newHistory := s.kravatte // needs to be a copy
		if s.kravatte.Vatte(tag, KravatteSANSETagSize*8, FlagNone) != 0 {
			return 1
		}
		// C = P + FK (T || 11 || e . history)
		s.kravatte = initalHistory
		if s.addToHistory(tag, KravatteSANSETagSize*8, 3, 2) != 0 {
			return 1
		}
		if s.kravatte.Vatte(ciphertext, dataBitLen, FlagLastPart) != 0 {
			return 1
		}
		memxoris(ciphertext, plaintext, dataBitLen)

		// history = P || 01 || e . history
		s.kravatte = newHistory
	} else {
		// T = 0t + FK (history)
		if s.kravatte.Vatte(tag, KravatteSANSETagSize*8, FlagNone) != 0 {
			return 1
		}
	}
	// e = e + 1
	s.e ^= 1

	return 0
}

// unwrap assumes all of these buffers have been preallocated to the correct length
func (s *sanse) unwrap(ciphertext []byte, plaintext []byte, dataBitLen int, ad []byte, adBitLen int, tag []byte) int {
	var tagPrime [KravatteSANSETagSize]byte

	// if |A| > 0 OR |C| = 0 then
	if adBitLen != 0 || dataBitLen == 0 {
		// history = A || 0 || e . history
		if s.addToHistory(ad, adBitLen, 0, 1) != 0 {
			return 1
		}
	}

	// if |C| > 0 then
	if dataBitLen != 0 {
		initalHistory := s.kravatte // need to copy

		// P = C + FK (T || 11 || e . history)
		if s.addToHistory(tag, KravatteSANSETagSize*8, 3, 2) != 0 {
			return 1
		}
		if s.kravatte.Vatte(plaintext, dataBitLen, FlagLastPart) != 0 {
			return 1
		}
		memxoris(plaintext, ciphertext, dataBitLen)

		// history = P || 01 || e . history
		s.kravatte = initalHistory
		if s.addToHistory(plaintext, dataBitLen, 2, 2) != 0 {
			return 1
		}
	}

	// T' = 0t + FK (history)
	if s.kravatte.Vatte(tagPrime[:], len(tagPrime)*8, FlagNone) != 0 {
		return 1
	}

	// e = e + 1
	s.e ^= 1

	// if T' != T then
	if subtle.ConstantTimeCompare(tagPrime[:], tag) != 1 {
		// wipe P, return error!
		return 1
	}
	// else return P
	return 0
}
