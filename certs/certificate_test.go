package certs

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

type keypair struct {
	public, private [KeyLen]byte
}

func fakeSignature() [SignatureLen]byte {
	var out [SignatureLen]byte
	rand.Read(out[:])
	return out
}

func TestWriteTo(t *testing.T) {
	var testKeyPair keypair
	rand.Read(testKeyPair.public[:])
	rand.Read(testKeyPair.private[:])
	c := Certificate{
		CertificateProtocolVersion: 1,
		CertificateType:            129,
		IssuedAt:                   time.Date(2020, 03, 11, 23, 35, 0, 0, time.UTC),
		ExpiresAt:                  time.Date(2021, 07, 04, 12, 1, 1, 0, time.UTC),
		IDChunk: IDChunk{
			Blocks: nil,
		},
		PublicKey: testKeyPair.public,
		Parent:    SHA256Fingerprint{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Signature: fakeSignature(),
	}
	b := &bytes.Buffer{}
	n, err := c.WriteTo(b)
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(867, n))
}
