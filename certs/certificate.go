package certs

import (
	"encoding/binary"
	"io"
	"time"
)

const KeyLen = 32
const SignatureLen = 64

type CertificateType byte

const (
	Version byte = 1

	Leaf         CertificateType = 1
	Intermediate CertificateType = 2
	Root         CertificateType = 3
)

type SHA256Fingerprint = [32]byte

type Certificate struct {
	CertificateProtocolVersion byte
	Type                       CertificateType
	IssuedAt                   time.Time
	ExpiresAt                  time.Time
	IDChunk                    IDChunk
	PublicKey                  [KeyLen]byte
	Parent                     SHA256Fingerprint
	Signature                  [SignatureLen]byte
}

type IDChunk struct {
	Blocks []IDBlock
}

type IDBlock struct {
	Flags    byte
	ServerID string
}

// WriteTo serializes a certificate and implements the io.WriterTo interface.
func (c *Certificate) WriteTo(w io.Writer) (int64, error) {
	var written int64
	n, err := w.Write([]byte{c.CertificateProtocolVersion, byte(c.Type)})
	written += int64(n)
	if err != nil {
		return written, err
	}
	err = binary.Write(w, binary.BigEndian, c.IssuedAt.Unix())
	if err != nil {
		return written, err
	}
	written += 8
	err = binary.Write(w, binary.BigEndian, c.ExpiresAt.Unix())
	if err != nil {
		return written, err
	}
	written += 8

	chunkLen, err := c.IDChunk.WriteTo(w)
	written += chunkLen
	if err != nil {
		return written, err
	}

	n, err = w.Write(c.PublicKey[:])
	written += int64(n)
	if err != nil {
		return written, err
	}

	n, err = w.Write(c.Parent[:])
	written += int64(n)
	if err != nil {
		return written, err
	}

	n, err = w.Write(c.Signature[:])
	written += int64(n)
	if err != nil {
		return written, err
	}

	return written, nil
}

func (chunk *IDChunk) WriteTo(w io.Writer) (int64, error) {
	panic("implement me")
}
