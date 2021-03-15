package certs

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	week = time.Hour * 7 * 24
)

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
func IssueLeaf(parent *Certificate, child *Identity) (*Certificate, error) {
	if parent.Type != Intermediate {
		return nil, errors.New("IssueLeaf requires the parent to be an intermediate")
	}
	if parent.Fingerprint == zero {
		return nil, errors.New("IssueLeaf requires the SHA256Fingeprint to be set")
	}
	if parent.privateKey == nil {
		return nil, errors.New("IssueLeaf requires a private key")
	}
	now := time.Now()
	out := &Certificate{
		Version:   Version,
		Type:      Leaf,
		IssuedAt:  time.Now(),
		ExpiresAt: now.Add(week),
		IDChunk: IDChunk{
			Blocks: NamesToBlocks(child.Names),
		},
		PublicKey: child.PublicKey,
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
	return out, nil
}
