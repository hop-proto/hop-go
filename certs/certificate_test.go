package certs

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"hop.computer/hop/keys"
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
			Blocks: []Name{
				{
					Type:  TypeDNSName,
					Label: []byte("example.domain"),
				},
			},
		},
		PublicKey: testKeyPair.public,
		Parent:    SHA3Fingerprint{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Signature: fakeSignature(),
	}
	assert.Check(t, c.PublicKey != zero)
	assert.Check(t, c.Parent != zero)

	b := &bytes.Buffer{}
	n, err := c.WriteTo(b)
	assert.NilError(t, err)
	assert.Check(t, cmp.Equal(int64(167), n))

	serialized := b.Bytes()
	assert.Check(t, cmp.Len(serialized, int(n)))

	expected := []byte{
		0x01, 0x01, 0x00, 0x00, // Version, Type, Reserved
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Issued
		0x0F, 0xED, 0xCB, 0xA0, 0x98, 0x76, 0x54, 0x32, // Expires
	}
	assert.Check(t, cmp.Len(expected, 20))
	expectedIDChunk := []byte{
		0x0, 0x13, // ID Chunk Len
		0x11, // IDBlock Len
		0x01, // DNSName
		0x0e, // ServerID length
		// example.domain
		0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e,
	}
	assert.Check(t, cmp.Len(expectedIDChunk, 19))
	assert.Assert(t, len(expected) < b.Len())
	front := serialized[:len(expected)]
	assert.Check(t, cmp.DeepEqual(expected, front))

	middle := serialized[len(expected) : len(expected)+32+32]
	assert.Assert(t, cmp.Len(middle, 32+32))
	assert.DeepEqual(t, middle[:32], c.PublicKey[:])
	assert.DeepEqual(t, middle[32:64], c.Parent[:])

	assert.Check(t, cmp.Equal(84, len(front)+len(middle)))

	back := serialized[len(expected)+32+32:]
	assert.Assert(t, cmp.Len(back, len(expectedIDChunk)+64))
	assert.DeepEqual(t, back[:len(expectedIDChunk)], expectedIDChunk)
	assert.DeepEqual(t, back[len(expectedIDChunk):], c.Signature[:])

	raw := make([]byte, b.Len())
	copy(raw, b.Bytes())

	d := Certificate{}
	n, err = d.ReadFrom(b)
	assert.Check(t, cmp.Equal(len(raw), int(n)))
	assert.NilError(t, err)

	assert.Equal(t, c.Version, d.Version)
	assert.Equal(t, c.Type, d.Type)
	assert.Equal(t, c.IssuedAt, d.IssuedAt)
	assert.Equal(t, c.ExpiresAt, d.ExpiresAt)
	assert.DeepEqual(t, c.IDChunk, d.IDChunk)
	assert.Equal(t, c.PublicKey, d.PublicKey)
	assert.Equal(t, c.PublicKey, testKeyPair.public)
	assert.Equal(t, c.Parent, d.Parent)
	assert.Equal(t, c.Signature, d.Signature)
	// TODO(dadrian): Fingerprint handling
	//assert.Equal(t, c.Fingerprint, d.Fingerprint)
}

func TestReadFiles(t *testing.T) {
	c, err := ReadCertificatePEMFile("testdata/leaf.pem")
	assert.NilError(t, err)

	pubKey, err := keys.ParseDHPublicKey(string(readFile(t, "testdata/leaf.pub")))
	assert.NilError(t, err)
	assert.DeepEqual(t, c.PublicKey[:], pubKey[:])

	p, err := ReadCertificatePEMFile("testdata/intermediate.pem")
	assert.NilError(t, err)
	assert.DeepEqual(t, c.Parent[:], p.Fingerprint[:])

	parentPubKey, err := keys.ParseSigningPublicKey(string(readFile(t, "testdata/intermediate.pub")))
	assert.NilError(t, err)
	assert.DeepEqual(t, p.PublicKey[:], parentPubKey[:])

	r, err := ReadCertificatePEMFile("testdata/root.pem")
	assert.NilError(t, err)
	assert.DeepEqual(t, p.Parent[:], r.Fingerprint[:])

	rootPubKey, err := keys.ParseSigningPublicKey(string(readFile(t, "testdata/root.pub")))
	assert.NilError(t, err)
	assert.DeepEqual(t, r.PublicKey[:], rootPubKey[:])

}

func open(t *testing.T, f string) *os.File {
	fd, err := os.Open(f)
	assert.NilError(t, err)
	return fd
}

func readFile(t *testing.T, f string) []byte {
	fd := open(t, f)
	b, err := ioutil.ReadAll(fd)
	assert.NilError(t, err)
	return b
}
