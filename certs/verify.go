package certs

import (
	"errors"

	"zmap.io/portal/keys"
)

// Identity is a set of names associated with a public key.
type Identity struct {
	PublicKey [KeyLen]byte
	Names     []Name
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
