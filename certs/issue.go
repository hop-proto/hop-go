package certs

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"

	"hop.computer/hop/keys"
)

const (
	week = time.Hour * 7 * 24
)

// issue does the heavy lifting of issuing and signing
func issue(parent *Certificate, child *Identity, certType CertificateType, duration time.Duration) (*Certificate, error) {
	if parent.Fingerprint == zero {
		return nil, errors.New("issue requires SHA3Fingerprint to be set")
	}
	if parent.privateKey == nil {
		return nil, errors.New("issue requires a private key")
	}
	now := time.Now()
	out := &Certificate{
		Version:   Version,
		Type:      certType,
		IssuedAt:  time.Now(),
		ExpiresAt: now.Add(week),
		IDChunk: IDChunk{
			Blocks: child.Names,
		},
		PublicKey: child.PublicKey[:],
		Parent:    parent.Fingerprint,
	}
	buf := bytes.Buffer{}
	n, err := out.WriteTo(&buf)
	if err != nil {
		return nil, err
	}
	if n < SignatureLen {
		logrus.Panicf("Certificate serialized to shorter than a signature, should not be possible (len %d)", n)
	}
	b := buf.Bytes()
	tbsLen := len(b) - SignatureLen

	// Using the RFC representation
	private := ed25519.NewKeyFromSeed(parent.privateKey[:])
	signature, err := private.Sign(rand.Reader, b[:tbsLen], crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if len(signature) != SignatureLen {
		logrus.Panicf("unexpected signature len %d (expected %d)", len(signature), SignatureLen)
	}
	copy(out.Signature[:], signature)
	h := sha3.New256()
	h.Write(b[:tbsLen])
	h.Write(out.Signature[:])
	h.Sum(out.Fingerprint[:0])
	out.raw = buf
	return out, nil
}

// IssueLeaf issues a Certificate with Type set to Leaf, using the provided
// parent, which must be an Intermediate with the private key set. All names
// will have the AuthorizationIndicator set to 0x0 (identify only).
//
// The parent private key is assumed to be an Ed25519 key, not an X25519 key.
// Similarly, the child Public is assumed to be an X25519, not an Ed25519
// key.
//
// TODO(dadrian): Do we need Authorization Indicator?
//
// TODO(dadrian): Should we just use XEdDSA so that we don't need to have two
// different key types, in exchange for having to implement more cryptography?
func IssueLeaf(parent *Certificate, child *Identity, cType CertificateType) (*Certificate, error) {
	if parent.Type != Intermediate {
		return nil, errors.New("IssueLeaf requires the parent to be an intermediate")
	}
	return issue(parent, child, cType, week)
}

func selfSign(self *Identity, certificateType CertificateType, keyPair *keys.SigningKeyPair) (*Certificate, error) {
	if keyPair != nil && !bytes.Equal(self.PublicKey[:], keyPair.Public[:]) {
		return nil, errors.New("key pair does not match identity")
	}
	now := time.Now()
	expiration := time.Date(now.Year()+5, now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), time.Local)
	out := &Certificate{
		Version:   Version,
		Type:      certificateType,
		IssuedAt:  now,
		ExpiresAt: expiration,
		IDChunk: IDChunk{
			Blocks: self.Names,
		},
		PublicKey:   self.PublicKey,
		Fingerprint: zero,
	}
	buf := bytes.Buffer{}
	n, err := out.WriteTo(&buf)
	if err != nil {
		return nil, err
	}
	if n < SignatureLen {
		logrus.Panicf("Certificate serialized to shorter than a signature and a parent fingerprint, should not be possible (len %d)", n)
	}
	b := buf.Bytes()
	tbsLen := len(b) - SignatureLen

	// Only add the signature if a key pair is provided.
	if keyPair != nil {
		private := ed25519.NewKeyFromSeed(keyPair.Private[:])
		signature, err := private.Sign(rand.Reader, b[:tbsLen], crypto.Hash(0))
		if err != nil {
			return nil, err
		}

		if len(signature) != SignatureLen {
			logrus.Panicf("unexpected signature len %d (expected %d)", len(signature), SignatureLen)
		}
		copy(out.Signature[:], signature)
	}
	h := sha3.New256()
	h.Write(b[:tbsLen])
	h.Write(out.Signature[:])
	h.Sum(out.Fingerprint[:0])
	out.raw = buf
	return out, nil
}

// SelfSignRoot issues a self-signed root certificate using the key in the key
// pair and the name in the Identity. The public keys for the Identity and the
// KeyPair must match.
//
// TODO(dadrian): This API is not great.
func SelfSignRoot(root *Identity, keyPair *keys.SigningKeyPair) (*Certificate, error) {
	return selfSign(root, Root, keyPair)
}

// IssueIntermediate issues an intermediate certificate, give a root. The root
// must have the private key set.
func IssueIntermediate(root *Certificate, intermediate *Identity) (*Certificate, error) {
	if root.Type != Root {
		return nil, errors.New("IssueIntermediate requires the parent to be a root")
	}
	return issue(root, intermediate, Intermediate, time.Hour*24*366)
}

// SelfSignLeaf issues self-signed leaf certificate using only a key.
func SelfSignLeaf(identity *Identity, cType CertificateType) (*Certificate, error) {
	return selfSign(identity, cType, nil)
}
