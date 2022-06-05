package certs

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"hop.computer/hop/keys"
)

// Identity is a set of names associated with a public key.
type Identity struct {
	PublicKey [KeyLen]byte
	Names     []Name
}

// SigningIdentity returns an Identity pointing to a public key with no name.
func SigningIdentity(key *keys.SigningKeyPair) *Identity {
	return &Identity{
		PublicKey: key.Public,
	}
}

// LeafIdentity returns an Identity bound to a X25519 public key with a set of
// names.
func LeafIdentity(key *keys.X25519KeyPair, names ...Name) *Identity {
	return &Identity{
		PublicKey: key.Public,
		Names:     names,
	}
}

// VerifyParent returns nil if parent issued child. An error is returned on any
// processing error (mismatched cert types, etc.), as well as for signature
// failures.
func VerifyParent(child *Certificate, parent *Certificate) error {
	switch child.Type {
	case Leaf:
		if parent.Type != Intermediate {
			return errors.New("leaf cert parent must be an intermediate")
		}
	case Intermediate:
		if parent.Type != Root {
			return errors.New("intermediate cert parent must be a root")
		}
	case Root:
		if parent.Type != Root {
			return errors.New("root cert parent must be a root")
		}
		if child.Parent != zero {
			return errors.New("root certificate must have zero'd fingerprint")
		}
	default:
		return errors.New("unknown cert type")
	}

	if child.Type != Root && child.Parent != parent.Fingerprint {
		return errors.New("mismatched parent/child")
	}

	if child.raw.Len() == 0 {
		return errors.New("child certificate does not have raw bytes stored, did you call ReadFrom?")
	}
	if child.raw.Len() < 64 {
		return errors.New("raw certificate truncated")
	}

	tbsLen := child.raw.Len() - 64
	tbs := child.raw.Bytes()[:tbsLen]
	ok := keys.VerifySignature((*keys.SigningPublicKey)(&parent.PublicKey), tbs, &child.Signature)
	if !ok {
		return errors.New("invalid signature")
	}
	return nil
}

// MatchesName returns true if the Certificate is a Leaf, and matches the
// provided name.
//
// TODO(dadrian): Add support for wildcard certificates.
func (c *Certificate) MatchesName(name Name) bool {
	switch c.Type {
	case Leaf:
		for _, b := range c.IDChunk.Blocks {
			if bytes.Equal(b.Label, name.Label) && b.Type == name.Type {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// Store is a set trusted certificates. Only roots are considered trusted.
// Non-root certificates may be provided for chain building, but they will not
// be trusted unless they chain to a root.
type Store struct {
	certs map[SHA3Fingerprint]*Certificate
}

// AddCertificate adds a certificate to a store.
func (s *Store) AddCertificate(c *Certificate) {
	if s.certs == nil {
		s.certs = make(map[SHA3Fingerprint]*Certificate)
	}
	s.certs[c.Fingerprint] = c
}

// Chain is chain of certificates, where chain[0] is a child, and
// chain[len(chain)-1] is a root. Each subsequent entry is a parent of the
// previous. Chains beginning with a leaf have length 3. Chains beginning with
// an intermediate have length 2. Chains beginning with a root have length 1.
type Chain []*Certificate

// VerificationFailureReason is an enum used with VerifyError that indicates why
// a certificate was unable to be verified.
type VerificationFailureReason int

// Known values of VerificationFailureReason
const (
	ReasonUnknownIntermediate VerificationFailureReason = iota
	ReasonUnknownRoot         VerificationFailureReason = iota
	ReasonMismatchedName      VerificationFailureReason = iota
	ReasonUnverifiedParent    VerificationFailureReason = iota
	ReasonUnexpectedType      VerificationFailureReason = iota
	ReasonInvalidCertificate  VerificationFailureReason = iota
	ReasonInternalError       VerificationFailureReason = iota
)

// String implements Stringer for VerificationFailureReason.
func (r VerificationFailureReason) String() string {
	switch r {
	case ReasonUnknownIntermediate:
		return "unknown intermediate"
	case ReasonUnknownRoot:
		return "unknown root"
	case ReasonMismatchedName:
		return "mismatched name"
	case ReasonUnverifiedParent:
		return "unverified parent"
	case ReasonUnexpectedType:
		return "unexpected certificate type"
	case ReasonInvalidCertificate:
		return "invalid certificate"
	case ReasonInternalError:
		return "internal error"
	default:
		return "unknown"
	}
}

// VerifyError implements error and is returned by VerifyLeaf.
type VerifyError interface {
	error
	Reason() VerificationFailureReason
}

type verifyError struct {
	reason VerificationFailureReason
	error
}

// Reason implements VerifyError
func (e *verifyError) Reason() VerificationFailureReason { return e.reason }

func unknownParent(fp, parent SHA3Fingerprint, expectedType CertificateType) VerifyError {
	reason := ReasonInternalError
	switch expectedType {
	case Intermediate:
		reason = ReasonUnknownIntermediate
	case Root:
		reason = ReasonUnknownRoot

	}
	return &verifyError{
		reason: reason,
		error:  fmt.Errorf("%s: cert %x with has unknown parent %x with expected type %s", reason, fp, parent, expectedType),
	}
}

func unverifiedParentError(c, parent *Certificate, err error) VerifyError {
	return &verifyError{
		reason: ReasonUnverifiedParent,
		error:  fmt.Errorf("%s: cert %x failed verification with %s parent %x: %w", ReasonUnverifiedParent, c.Fingerprint, parent.Type, parent.Fingerprint, err),
	}
}

func internalVerifyError(err error) VerifyError {
	return &verifyError{
		reason: ReasonInternalError,
		error:  fmt.Errorf("%s: %w", ReasonInternalError, err),
	}
}

func unexpectedTypeError(c *Certificate, expectedType CertificateType) error {
	return &verifyError{
		reason: ReasonInvalidCertificate,
		error:  fmt.Errorf("%s: expected %x to have certificate type %s, has %s", ReasonUnexpectedType, c.Fingerprint, expectedType, c.Type),
	}
}

func mismatchedName(c *Certificate, target Name) error {
	return &verifyError{
		reason: ReasonMismatchedName,
		error:  fmt.Errorf("%s: %x not valid for name %d:%s", ReasonMismatchedName, c.Fingerprint, target.Type, target.Label),
	}
}

// VerifyOptions holds parameters to VerifyLeaf.
type VerifyOptions struct {
	// PresentedIntermediate will be used to build a verified chain if it is
	// non-nil and matches a parent of the leaf. If it is not a valid parent of
	// the leaf, it is ignored.
	PresentedIntermediate *Certificate

	// Name is compared to the name on the leaf certificate if it is non-zero.
	Name Name
}

// VerifyLeaf verifies that the leaf chains up to a root in the store. It takes
// a struct of VerifyOptions, which can include a presented intermediate, if the
// verifier is not already aware of an expected intermediate.
//
// TODO(dadrian): Name constraints
func (s Store) VerifyLeaf(leaf *Certificate, opts VerifyOptions) error {
	if leaf.Type != Leaf {
		return unexpectedTypeError(leaf, Leaf)
	}
	if !opts.Name.IsZero() && !leaf.MatchesName(opts.Name) {
		return mismatchedName(leaf, opts.Name)
	}
	var intermediate *Certificate
	if opts.PresentedIntermediate != nil && leaf.Parent == opts.PresentedIntermediate.Fingerprint {
		intermediate = opts.PresentedIntermediate
	} else if parent, ok := s.certs[leaf.Parent]; ok {
		intermediate = parent
	} else {
		return unknownParent(leaf.Fingerprint, leaf.Parent, Intermediate)
	}

	if intermediate.Type != Intermediate {
		return unexpectedTypeError(intermediate, Intermediate)
	}
	if intermediate.Fingerprint != leaf.Parent {
		// Should not happen with a well-formed Store
		return internalVerifyError(fmt.Errorf("expected intermediate %x to have fingerprint %x", intermediate.Fingerprint, leaf.Parent))
	}

	if err := VerifyParent(leaf, intermediate); err != nil {
		return unverifiedParentError(leaf, intermediate, err)
	}
	root, ok := s.certs[intermediate.Parent]
	if !ok {
		return unknownParent(intermediate.Fingerprint, intermediate.Parent, Root)
	}
	if root.Type != Root {
		return unexpectedTypeError(root, Root)
	}
	if root.Fingerprint != intermediate.Parent {
		// Should not happen with a well-formed Store
		return internalVerifyError(fmt.Errorf("expected root %x to have fingerprint %x", root.Fingerprint, intermediate.Parent))
	}
	if err := VerifyParent(intermediate, root); err != nil {
		return unverifiedParentError(intermediate, root, err)
	}

	return nil
}

// LoadRootStoreFromPEMFile allocates a new Store from a set of certificates
// encoded in PEM format in a single file.
func LoadRootStoreFromPEMFile(path string) (*Store, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	certs, err := ReadManyCertificatesPEM(fd)
	if err != nil {
		return nil, err
	}
	out := new(Store)
	for i := range certs {
		out.AddCertificate(&certs[i])
	}
	return out, nil
}
