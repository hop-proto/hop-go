package certs

import (
	"testing"

	"gotest.tools/assert"
)

func TestVerifyParent(t *testing.T) {
	root, err := ReadCertificatePEMFile("testdata/root.pem")
	assert.NilError(t, err)
	intermediate, err := ReadCertificatePEMFile("testdata/intermediate.pem")
	assert.NilError(t, err)
	leaf, err := ReadCertificatePEMFile("testdata/leaf.pem")
	assert.NilError(t, err)

	err = VerifyParent(leaf, leaf)
	assert.Check(t, err != nil)
	err = VerifyParent(leaf, intermediate)
	assert.Check(t, err)
	err = VerifyParent(leaf, root)
	assert.Check(t, err != nil)

	err = VerifyParent(intermediate, leaf)
	assert.Check(t, err != nil)
	err = VerifyParent(intermediate, intermediate)
	assert.Check(t, err != nil)
	err = VerifyParent(intermediate, root)
	assert.Check(t, err)

	err = VerifyParent(root, leaf)
	assert.Check(t, err != nil)
	err = VerifyParent(root, intermediate)
	assert.Check(t, err != nil)
	err = VerifyParent(root, root)
	assert.Check(t, err)

	leaf.Signature[0]++
	err = VerifyParent(leaf, intermediate)
	assert.Check(t, err != nil)

	intermediate.Signature[1]++
	err = VerifyParent(intermediate, root)
	assert.Check(t, err != nil)

	root.Signature[63]++
	err = VerifyParent(root, root)
	assert.Check(t, err != nil)
}

func TestVerifyLeaf(t *testing.T) {
	root, err := ReadCertificatePEMFile("testdata/root.pem")
	assert.NilError(t, err)
	intermediate, err := ReadCertificatePEMFile("testdata/intermediate.pem")
	assert.NilError(t, err)
	leaf, err := ReadCertificatePEMFile("testdata/leaf.pem")
	assert.NilError(t, err)

	// Empty Storej
	s := Store{}
	err = s.VerifyLeaf(leaf, VerifyOptions{
		PresentedIntermediate: intermediate,
	})
	assert.ErrorContains(t, err, ReasonUnknownRoot.String())

	// Only the root
	s.AddCertificate(root)

	err = s.VerifyLeaf(leaf, VerifyOptions{})
	assert.ErrorContains(t, err, ReasonUnknownIntermediate.String())
	err = s.VerifyLeaf(leaf, VerifyOptions{
		PresentedIntermediate: intermediate,
	})
	assert.NilError(t, err)

	// Add the intermediate
	s.AddCertificate(intermediate)
	err = s.VerifyLeaf(leaf, VerifyOptions{})
	assert.NilError(t, err)

	// Name matching
	err = s.VerifyLeaf(leaf, VerifyOptions{
		Name: DNSName("domain.example"),
	})
	assert.NilError(t, err)
	err = s.VerifyLeaf(leaf, VerifyOptions{
		Name: DNSName("wrongdomain.example"),
	})
	assert.ErrorContains(t, err, ReasonMismatchedName.String())

	// TODO(dadrian): Test all the error conditions
}
