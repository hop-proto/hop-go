package certs

import (
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"zmap.io/portal/keys"
)

func TestIssueSelfSigned(t *testing.T) {
	k, err := keys.ReadDHKeyFromPEMFile("testdata/leaf-key.pem")
	assert.NilError(t, err, "unable to open DH leaf")

	// Check that we can self-sign certs with and without names.
	identities := []Identity{
		{
			PublicKey: k.Public,
			Names: []Name{
				DNSName("dadrian.io"),
				RawStringName("d a v e"),
			},
		},
		{
			PublicKey: k.Public,
		},
	}

	for i := range identities {
		c, err := SelfSignLeaf(&identities[i])
		assert.NilError(t, err)
		assert.Check(t, cmp.DeepEqual(c.Signature, zeroSignature), i)
		assert.Check(t, c.Fingerprint != zero)
		assert.Check(t, cmp.DeepEqual(c.PublicKey[:], k.Public[:]), i)
		assert.Check(t, cmp.DeepEqual(c.IDChunk.Blocks, identities[i].Names), i)
	}
}
