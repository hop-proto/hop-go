package certs

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
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
	var issued int64 = 0x0102030405060708
	var expires int64 = 0x0FEDCBA098765432
	c := Certificate{
		Version:   1,
		Type:      Leaf,
		IssuedAt:  time.Unix(issued, 0),
		ExpiresAt: time.Unix(expires, 0),
		IDChunk: IDChunk{
			Blocks: []IDBlock{
				{
					Flags:    byte(DNSName),
					ServerID: "example.domain",
				},
			},
		},
		PublicKey: testKeyPair.public,
		Parent:    SHA256Fingerprint{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Signature: fakeSignature(),
	}
	assert.Check(t, c.PublicKey != zero)
	assert.Check(t, c.Parent != zero)

	b := &bytes.Buffer{}
	n, err := c.WriteTo(b)
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(int64(172), n))

	serialized := b.Bytes()
	assert.Check(t, cmp.Len(serialized, 172))

	expected := []byte{
		0x01, 0x01, 0x00, 0x00, // Version, Type, Reserved
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Issued
		0x0F, 0xED, 0xCB, 0xA0, 0x98, 0x76, 0x54, 0x32, // Expires
		0x0, 0x18, // ID Chunk Len
		0x00, 0x00, // ID Chunk Padding Len
		0x14, // IDBlock Len
		0x01, // DNSName
		0x0e, // ServerID length
		// example.domain
		0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e,
		0x00, 0x00, 0x00, // IDBlock padding
		// No IDChunk padding
	}
	assert.Assert(t, len(expected) < b.Len())
	var front []byte = serialized[:len(expected)]
	assert.Check(t, cmp.DeepEqual(expected, front))

	back := serialized[len(expected):]
	assert.Check(t, cmp.Len(back, 32+32+64))
	assert.DeepEqual(t, back[:32], c.PublicKey[:])
	assert.DeepEqual(t, back[32:64], c.Parent[:])
	assert.DeepEqual(t, back[64:], c.Signature[:])
}

func TestReadFrom(t *testing.T) {
	// TODO(dadrian): Test
}

func TestReadAndWriteAreInverse(t *testing.T) {
	rawBase64 := "AQMAAAAAAABgWmMCAAAAAGnBtgIACAAABAEAAJ/Uvy+Aw+SPm6MTWdSOziXbDwkW7kQMBwvhBCWUervrAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC8j60pq235F+PjfsFl42f29olJ3qae/nihqTg2ibPJHF/Xa7aPiQ85WX4AGNoU0dAVhmVazIsXPCqiLf0gtuUN"
	raw, err := base64.StdEncoding.DecodeString(rawBase64)
	assert.NilError(t, err)
	c := Certificate{}
	n, err := c.ReadFrom(bytes.NewBuffer(raw))
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(len(raw), int(n)))
	assert.Check(t, cmp.Equal(c.IDChunk.SerializedLen(), 8))
	buf := bytes.Buffer{}
	written, err := c.WriteTo(&buf)
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(n, written))
	assert.Check(t, cmp.DeepEqual(raw, buf.Bytes()))
}

func TestPublicKeyManual(t *testing.T) {
	pemString := `-----BEGIN HOP CERTIFICATE-----
AQMAAAAAAABgWmMCAAAAAGnBtgIACAAABAEAAJ/Uvy+Aw+SPm6MTWdSOziXbDwkW
7kQMBwvhBCWUervrAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC8j60p
q235F+PjfsFl42f29olJ3qae/nihqTg2ibPJHF/Xa7aPiQ85WX4AGNoU0dAVhmVa
zIsXPCqiLf0gtuUN
-----END HOP CERTIFICATE-----
`

	c, err := ReadCertificatePEM([]byte(pemString))
	assert.NilError(t, err)
	assert.Check(t, c != nil)

	expectedPublic, _ := base64.StdEncoding.DecodeString("n9S/L4DD5I+boxNZ1I7OJdsPCRbuRAwHC+EEJZR6u+s=")
	assert.Check(t, cmp.Len(expectedPublic, 32))
	assert.Check(t, cmp.Len(c.PublicKey[:], 32))
	assert.Check(t, cmp.DeepEqual(expectedPublic[:], c.PublicKey[:]))
}
