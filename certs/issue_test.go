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

func TestIssueLeafAt(t *testing.T) {
	rootKey := keys.GenerateNewSigningKeyPair()
	root, err := SelfSignRoot(SigningIdentity(rootKey), rootKey)
	assert.NilError(t, err)
	assert.NilError(t, root.ProvideKey((*[32]byte)(&rootKey.Private)))

	intermediateKey := keys.GenerateNewSigningKeyPair()
	intermediate, err := IssueIntermediate(root, SigningIdentity(intermediateKey))
	assert.NilError(t, err)
	assert.NilError(t, intermediate.ProvideKey((*[32]byte)(&intermediateKey.Private)))

	leafKey := keys.GenerateNewX25519KeyPair()
	issuedAt := intermediate.IssuedAt
	leaf, err := IssueLeafAt(
		intermediate,
		LeafIdentity(leafKey, RawStringName("short-lived")),
		issuedAt,
		time.Hour,
	)
	assert.NilError(t, err)
	assert.Equal(t, leaf.IssuedAt, issuedAt)
	assert.Equal(t, leaf.ExpiresAt, issuedAt.Add(time.Hour))
	assert.NilError(t, VerifyParent(leaf, intermediate))

	_, err = IssueLeafAt(intermediate, LeafIdentity(leafKey), intermediate.ExpiresAt, time.Hour)
	assert.ErrorContains(t, err, "valid at issuance time")
}

func TestIssueLeafWithValidityUsesCurrentTime(t *testing.T) {
	rootKey := keys.GenerateNewSigningKeyPair()
	root, err := SelfSignRoot(SigningIdentity(rootKey), rootKey)
	assert.NilError(t, err)
	assert.NilError(t, root.ProvideKey((*[32]byte)(&rootKey.Private)))

	intermediateKey := keys.GenerateNewSigningKeyPair()
	intermediate, err := IssueIntermediate(root, SigningIdentity(intermediateKey))
	assert.NilError(t, err)
	assert.NilError(t, intermediate.ProvideKey((*[32]byte)(&intermediateKey.Private)))

	before := time.Now()
	leafKey := keys.GenerateNewX25519KeyPair()
	leaf, err := IssueLeafWithValidity(intermediate, LeafIdentity(leafKey), time.Hour)
	after := time.Now()
	assert.NilError(t, err)
	assert.Check(t, !leaf.IssuedAt.Before(before))
	assert.Check(t, !leaf.IssuedAt.After(after))
	assert.Equal(t, leaf.ExpiresAt, leaf.IssuedAt.Add(time.Hour))
}
