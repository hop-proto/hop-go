package certs

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

// Byte-length constants for cryptographic material
const (
	KeyLen       = 32
	SignatureLen = 64
)

// ErrNameTooLong is returned when a name does not fit in an IDBlock.
var ErrNameTooLong = errors.New("maximum name length is 252 bytes")

// CertificateType flags whether a certificate is a Leaf, Intermediate, or Root.
type CertificateType byte

// Known CertificateType values
const (
	Leaf         CertificateType = 1
	Intermediate CertificateType = 2
	Root         CertificateType = 3
)

func CertificateTypeFromString(typeStr string) (CertificateType, error) {
	s := strings.ToLower(typeStr)
	switch s {
	case "leaf":
		return Leaf, nil
	case "intermediate":
		return Intermediate, nil
	case "root":
		return Root, nil
	default:
		return 0, fmt.Errorf("unknown certificate type: %s", typeStr)
	}
}

const (
	// SHA256Len is the length of a SHA256Fingerprint array
	SHA256Len = 32

	// Protocol version
	Version byte = 1
)

// SHA256Fingerprint is used to identify the parent of a Certificate.
type SHA256Fingerprint = [SHA256Len]byte

var zero SHA256Fingerprint

// Certificate represent a Hop certificate, and can be serialized to and from
// bytes. A Certificate can optionally be associated with its corresponding
// private key.
type Certificate struct {
	Version   byte
	Type      CertificateType
	IssuedAt  time.Time
	ExpiresAt time.Time
	IDChunk   IDChunk
	PublicKey [KeyLen]byte
	Parent    SHA256Fingerprint
	Signature [SignatureLen]byte

	// Fingerprint is the SHA256Fingerprint of the certificate. It is populated
	// when a certificate is read, or issued.
	Fingerprint SHA256Fingerprint

	privateKey *[KeyLen]byte
}

// IDChunk contains the IDBlocks in a certificate
type IDChunk struct {
	Blocks []IDBlock
}

// IDBlock is the serialization structure for a Name.
type IDBlock struct {
	Flags    byte
	ServerID string
}

// WriteTo serializes a certificate and implements the io.WriterTo interface.
func (c *Certificate) WriteTo(w io.Writer) (int64, error) {
	var written int64
	n, err := w.Write([]byte{c.Version, byte(c.Type), 0, 0})
	written += int64(n)
	if err != nil {
		return written, err
	}

	//idChunkLen := c.IDChunk.SerializedLen()
	//binary.Write(w, binary.BigEndian, uint16(idChunkLen))

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

// ReadFrom populates a certificate from serialized bytes.
func (c *Certificate) ReadFrom(r io.Reader) (int64, error) {
	var bytesRead int64
	var err error
	err = binary.Read(r, binary.BigEndian, &c.Version)
	if err != nil {
		return bytesRead, err
	}
	bytesRead++

	err = binary.Read(r, binary.BigEndian, &c.Type)
	if err != nil {
		return bytesRead, err
	}
	bytesRead++

	var reserved uint16
	err = binary.Read(r, binary.BigEndian, &reserved)
	if err != nil {
		return bytesRead, err
	}
	bytesRead += 2

	var t uint64
	err = binary.Read(r, binary.BigEndian, &t)
	if err != nil {
		return bytesRead, err
	}
	if t > math.MaxInt64 {
		return bytesRead, errors.New("issue timestamp too large")
	}
	bytesRead += 8
	c.IssuedAt = time.Unix(int64(t), 0)

	err = binary.Read(r, binary.BigEndian, &t)
	if err != nil {
		return bytesRead, err
	}
	if t > math.MaxInt64 {
		return bytesRead, errors.New("expires timestamp too large")
	}
	bytesRead += 8
	c.ExpiresAt = time.Unix(int64(t), 0)

	chunkLen, err := c.IDChunk.ReadFrom(r)
	bytesRead += chunkLen
	if err != nil {
		return bytesRead, err
	}
	n, err := r.Read(c.PublicKey[:])
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	if n != KeyLen {
		return bytesRead, io.EOF
	}

	n, err = r.Read(c.Parent[:])
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	if n != SHA256Len {
		return bytesRead, io.EOF
	}

	n, err = r.Read(c.Signature[:])
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	if n != SignatureLen {
		return bytesRead, io.EOF
	}

	return bytesRead, nil
}

// RoundUpToWord round i up to the nearest multiple of 4.
func RoundUpToWord(i int) int {
	r := i % 4
	if r == 0 {
		return i
	}
	return i + (4 - r)
}

// SerializedLen returns the length of this IDChunk if it were to be serialized.
// It does not serialize the IDChunk.
func (chunk *IDChunk) SerializedLen() int {
	outputLen := 0
	for i := range chunk.Blocks {
		blockSize, _ := chunk.Blocks[i].BlockSize()
		outputLen += blockSize
	}
	return outputLen
}

// BlockSize returns the length of this block when serialized, and how many
// bytes of the serialization are padding. The padding is included in the block
// size.
func (b *IDBlock) BlockSize() (blockSize int, padding int) {
	base := len(b.ServerID) + 3
	return RoundUpToWord(base), base
}

// WriteTo serializes the IDBlock to w.
func (b *IDBlock) WriteTo(w io.Writer) (int64, error) {
	blockSize, paddingLen := b.BlockSize()
	if blockSize > 256 {
		return 0, ErrNameTooLong
	}
	// TODO(dadrian): Flags
	written := int64(0)
	n, err := w.Write([]byte{byte(blockSize), 0})
	written += int64(n)
	if err != nil {
		return written, err
	}
	n, err = w.Write([]byte(b.ServerID))
	written += int64(n)
	for i := 0; i < paddingLen; i++ {
		n, err = w.Write([]byte{0})
		written += int64(n)
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// ReadFrom reads a serialized IDBlock from r.
func (b *IDBlock) ReadFrom(r io.Reader) (int64, error) {
	var bytesRead int64

	var blockSize byte
	err := binary.Read(r, binary.BigEndian, &blockSize)
	if err != nil {
		return bytesRead, err
	}
	bytesRead++
	if blockSize < 3 {
		return bytesRead, fmt.Errorf("minium block size is 3, got %d", blockSize)
	}

	var flags byte
	err = binary.Read(r, binary.BigEndian, &flags)
	if err != nil {
		return bytesRead, err
	}
	bytesRead++

	var serverIDLen byte
	err = binary.Read(r, binary.BigEndian, &serverIDLen)
	if err != nil {
		return bytesRead, err
	}
	bytesRead++

	if serverIDLen > blockSize-3 {
		return bytesRead, fmt.Errorf("invalid server ID len %d (max for block size %d is %d)", serverIDLen, blockSize, blockSize-3)
	}

	// TODO(dadrian): Maybe IDBlock should store an []byte, then we can avoid
	// this allocation.
	builder := strings.Builder{}
	copied, err := io.CopyN(&builder, r, int64(serverIDLen))
	bytesRead += copied
	if err != nil {
		return bytesRead, err
	}

	paddingLen := int(blockSize - 3 - serverIDLen)
	expectedPadding := make([]byte, paddingLen)
	padding := make([]byte, paddingLen)
	n, err := r.Read(padding)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	if n != paddingLen {
		return bytesRead, io.EOF
	}
	if subtle.ConstantTimeCompare(expectedPadding, padding) != 1 {
		return bytesRead, errors.New("invalid padding")
	}
	return bytesRead, nil
}

// ReadFrom reads an IDChunk from r.
func (chunk *IDChunk) ReadFrom(r io.Reader) (int64, error) {
	var bytesRead int64
	var chunkLen uint16
	err := binary.Read(r, binary.BigEndian, &chunkLen)
	if err != nil {
		return bytesRead, err
	}
	bytesRead += 2

	var paddingLen uint16
	err = binary.Read(r, binary.BigEndian, &paddingLen)
	if err != nil {
		return bytesRead, err
	}
	bytesRead += 2

	if chunkLen > 512 {
		return bytesRead, fmt.Errorf("invalid IDChunk length %d", chunkLen)
	}
	if paddingLen > chunkLen {
		return bytesRead, fmt.Errorf("invalid IDChunk padding length %d (IDChunk only %d)", paddingLen, chunkLen)
	}

	blockLen := chunkLen - paddingLen
	for bytesRead < int64(blockLen) {
		block := IDBlock{}
		n, err := block.ReadFrom(r)
		bytesRead += n
		if err != nil {
			return bytesRead, err
		}
	}

	padding := make([]byte, paddingLen)
	expectedPadding := make([]byte, paddingLen)
	n, err := r.Read(padding)
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	if subtle.ConstantTimeCompare(expectedPadding, padding) != 1 {
		return bytesRead, errors.New("invalid padding")
	}
	return bytesRead, nil
}

// WriteTo writes an IDChunk to w.
func (chunk *IDChunk) WriteTo(w io.Writer) (int64, error) {
	var written int64
	serializedLen := chunk.SerializedLen()
	if serializedLen > 512 {
		return 0, fmt.Errorf("invalid chunk len %d (max is 512)", serializedLen)
	}
	err := binary.Write(w, binary.BigEndian, uint16(serializedLen))
	if err != nil {
		return written, err
	}
	written += 2

	// TODO(dadrian): Add in non-zero padding
	err = binary.Write(w, binary.BigEndian, uint16(0))
	if err != nil {
		return written, err
	}
	written += 2

	for i := range chunk.Blocks {
		n, err := chunk.Blocks[i].WriteTo(w)
		written += int64(n)
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

const PEMTypeHopCertificate = "HOP CERTIFICATE"

// EncodeCertificateToPEM returns the PEM-encoded bytes of the certificate.
func EncodeCertificateToPEM(c *Certificate) ([]byte, error) {
	buf := bytes.Buffer{}
	_, err := c.WriteTo(&buf)
	if err != nil {
		return nil, err
	}
	p := pem.Block{
		Type:  PEMTypeHopCertificate,
		Bytes: buf.Bytes(),
	}
	return pem.EncodeToMemory(&p), nil
}
