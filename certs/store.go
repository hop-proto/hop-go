package certs

import (
	"fmt"
)

// Store is a set trusted certificates. Only roots are considered trusted.
// Non-root certificates may be provided for chain building, but they will not
// be trusted unless they chain to a root.
type Store struct {
	certs map[SHA3Fingerprint]*Certificate
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
	ReasonInvalidCertificate  VerificationFailureReason = iota
	ReasonInvalidParent       VerificationFailureReason = iota
	ReasonInternalFailure     VerificationFailureReason = iota
)

func (r VerificationFailureReason) String() string {
	switch r {
	case ReasonUnknownIntermediate:
		return "unknown intermediate"
	case ReasonUnknownRoot:
		return "unknown root"
	case ReasonMismatchedName:
		return "mismatched name"
	case ReasonInvalidCertificate:
		return "invalid certificate"
	case ReasonInvalidParent:
		return "invalid parent"
	case ReasonInternalFailure:
		return "internal error"
	default:
		return "unknown"
	}
}

// VerifyError implements error and is returned by Verify.
type VerifyError interface {
	error
	Reason() VerificationFailureReason
}

type verifyError struct {
	reason VerificationFailureReason
	error
}

func (e *verifyError) Reason() VerificationFailureReason { return e.reason }

func unknownParent(fp, parent SHA3Fingerprint, expectedType CertificateType) VerifyError {
	reason := ReasonInternalFailure
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

func unknownRootError(fp SHA3Fingerprint) VerifyError {
	return &verifyError{
		reason: ReasonUnknownRoot,
		error:  fmt.Errorf("%s: unknown root cert %x", ReasonUnknownRoot, fp),
	}
}

func invalidParentError(c, parent *Certificate, err error) VerifyError {
	return &verifyError{
		reason: ReasonInvalidParent,
		error:  fmt.Errorf("%s: cert %x failed verification with %s parent %x: %w", ReasonInvalidParent, c.Fingerprint, parent.Type, parent.Fingerprint, err),
	}
}

func invalidCertError(fp SHA3Fingerprint, err error) VerifyError {
	return &verifyError{
		reason: ReasonInvalidCertificate,
		error:  fmt.Errorf("%s: cert %x: %w", ReasonInvalidCertificate, fp, err),
	}
}

func internalVerifyError(err error) VerifyError {
	return &verifyError{
		reason: ReasonInternalFailure,
		error:  err,
	}
}

// BuildVerifiedChain returns a verified chain for the provided certificate
func (s Store) BuildVerifiedChain(c *Certificate) (Chain, error) {
	var chain [3]*Certificate
	i := 0

	switch c.Type {
	case Leaf:
		chain[i] = c
		i++
		intermediate, ok := s.certs[c.Parent]
		if !ok {
			return nil, unknownParent(c.Fingerprint, c.Parent, Intermediate)
		}
		if intermediate.Fingerprint != c.Parent {
			return nil, internalVerifyError(fmt.Errorf("expected %x to have fingerprint %x", intermediate.Fingerprint, c.Parent))
		}
		if err := VerifyParent(c, intermediate); err != nil {
			return nil, invalidParentError(c, intermediate, err)
		}
		c = intermediate
		fallthrough
	case Intermediate:
		chain[i] = c
		i++
		root, ok := s.certs[c.Parent]
		if !ok {
			return nil, unknownParent(c.Fingerprint, c.Parent, Root)
		}
		if root.Fingerprint != c.Parent {
			return nil, internalVerifyError(fmt.Errorf("expected %x to have fingerprint %x", root.Fingerprint, c.Parent))
		}
		if err := VerifyParent(c, root); err != nil {
			return nil, invalidParentError(c, root, err)
		}
		c = root
		fallthrough
	case Root:
		chain[i] = c
		i++
		self, ok := s.certs[c.Fingerprint]
		if !ok {
			return nil, unknownRootError(c.Fingerprint)
		}
		if self.Fingerprint != c.Fingerprint {
			return nil, internalVerifyError(fmt.Errorf("self-root lookup had mismatched fingerprints: expected %x, got %x", c.Fingerprint, self.Fingerprint))
		}

		if err := VerifyParent(c, self); err != nil {
			return nil, invalidParentError(c, self, err)
		}
	default:
		return nil, invalidCertError(c.Fingerprint, fmt.Errorf("unknown cert type %d", c.Type))
	}
	out := chain[:i]
	return out, nil
}
