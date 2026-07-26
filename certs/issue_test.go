package certs

import (
	"testing"
	"time"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	"hop.computer/hop/keys"
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

func TestIssueLeafWithValidity(t *testing.T) {
	rootKey := keys.GenerateNewSigningKeyPair()
	root, err := SelfSignRoot(SigningIdentity(rootKey), rootKey)
	assert.NilError(t, err)
	assert.NilError(t, root.ProvideKey((*[32]byte)(&rootKey.Private)))

	intermediateKey := keys.GenerateNewSigningKeyPair()
	intermediate, err := IssueIntermediate(root, SigningIdentity(intermediateKey))
	assert.NilError(t, err)
	assert.NilError(t, intermediate.ProvideKey((*[32]byte)(&intermediateKey.Private)))

	leafKey := keys.GenerateNewX25519KeyPair()
	leaf, err := IssueLeafWithValidity(intermediate, LeafIdentity(leafKey, RawStringName("short-lived")), time.Hour)
	assert.NilError(t, err)
	assert.Check(t, leaf.ExpiresAt.Sub(leaf.IssuedAt) >= time.Hour-time.Second)
	assert.Check(t, leaf.ExpiresAt.Sub(leaf.IssuedAt) <= time.Hour+time.Second)
	assert.NilError(t, VerifyParent(leaf, intermediate))

	intermediate.ExpiresAt = time.Now().Add(-time.Second)
	_, err = IssueLeafWithValidity(intermediate, LeafIdentity(leafKey), time.Hour)
	assert.ErrorContains(t, err, "currently valid parent")
}
