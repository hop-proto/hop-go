package certs

import (
	"testing"
	"time"

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
	validTime := leaf.IssuedAt.Add(time.Second)

	// Empty Storej
	s := Store{}
	err = s.VerifyLeaf(leaf, VerifyOptions{
		PresentedIntermediate: intermediate,
		CurrentTime:           validTime,
	})
	assert.ErrorContains(t, err, ReasonUnknownRoot.String())

	// Only the root
	s.AddCertificate(root)

	err = s.VerifyLeaf(leaf, VerifyOptions{CurrentTime: validTime})
	assert.ErrorContains(t, err, ReasonUnknownIntermediate.String())
	err = s.VerifyLeaf(leaf, VerifyOptions{
		PresentedIntermediate: intermediate,
		CurrentTime:           validTime,
	})
	assert.NilError(t, err)

	// Add the intermediate
	s.AddCertificate(intermediate)
	err = s.VerifyLeaf(leaf, VerifyOptions{CurrentTime: validTime})
	assert.NilError(t, err)

	// Name matching
	err = s.VerifyLeaf(leaf, VerifyOptions{
		Name:        DNSName("domain.example"),
		CurrentTime: validTime,
	})
	assert.NilError(t, err)
	err = s.VerifyLeaf(leaf, VerifyOptions{
		Name:        DNSName("wrongdomain.example"),
		CurrentTime: validTime,
	})
	assert.ErrorContains(t, err, ReasonMismatchedName.String())

	err = s.VerifyLeaf(leaf, VerifyOptions{CurrentTime: leaf.IssuedAt.Add(-time.Second)})
	assert.ErrorContains(t, err, ReasonTimeInvalid.String())
	err = s.VerifyLeaf(leaf, VerifyOptions{CurrentTime: leaf.ExpiresAt})
	assert.ErrorContains(t, err, ReasonTimeInvalid.String())

	intermediateExpiry := intermediate.ExpiresAt
	intermediate.ExpiresAt = validTime
	err = s.VerifyLeaf(leaf, VerifyOptions{CurrentTime: validTime})
	assert.ErrorContains(t, err, ReasonTimeInvalid.String())
	intermediate.ExpiresAt = intermediateExpiry

	rootExpiry := root.ExpiresAt
	root.ExpiresAt = validTime
	err = s.VerifyLeaf(leaf, VerifyOptions{CurrentTime: validTime})
	assert.ErrorContains(t, err, ReasonTimeInvalid.String())
	root.ExpiresAt = rootExpiry

	// TODO(dadrian): Test all the error conditions
}
