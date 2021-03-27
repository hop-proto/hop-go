package certs

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/keys"
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

// CertificateTypeFromString returns a CertificateType based on its name. It is
// case-insensitive.
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

	raw bytes.Buffer
}

// IDType indicates the type of an identifier label, e.g. DNSName, IPAddress, etc.
type IDType byte

// Known IDType values
const (
	DNSName   IDType = 0x01
	IPAddress IDType = 0x02
)

// Name is a UTF-8 label and an IDType. It can be encoded to an IDBlock.
type Name struct {
	Label string
	Type  IDType
}

// IDChunk contains the IDBlocks in a certificate
type IDChunk struct {
	Blocks []Name
}

// WriteTo serializes a certificate and implements the io.WriterTo interface.
func (c *Certificate) WriteTo(w io.Writer) (int64, error) {
	var written int64
	n, err := w.Write([]byte{c.Version, byte(c.Type), 0, 0})
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

// ReadFrom populates a certificate from serialized bytes.
func (c *Certificate) ReadFrom(r io.Reader) (int64, error) {
	var bytesRead int64
	var err error

	// Save the bytes
	c.raw.Reset()
	tee := io.TeeReader(r, &c.raw)

	// Calculate hash as we read
	h := sha256.New()
	r = io.TeeReader(tee, h)

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

	// The hash has been written via the TeeReader, read it out.
	h.Sum(c.Fingerprint[:0])

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
	outputLen := 4
	for i := range chunk.Blocks {
		blockSize, _ := chunk.Blocks[i].BlockSize()
		outputLen += blockSize
	}
	return outputLen
}

// BlockSize returns the length of this block when serialized, and how many
// bytes of the serialization are padding. The padding is included in the block
// size.
func (name *Name) BlockSize() (blockSize int, padding int) {
	base := len(name.Label) + 3
	total := RoundUpToWord(base)
	return total, total - base
}

// WriteTo serializes the IDBlock to w.
func (name *Name) WriteTo(w io.Writer) (int64, error) {
	blockSize, paddingLen := name.BlockSize()
	if blockSize > 256 {
		return 0, ErrNameTooLong
	}
	idLen := len(name.Label)
	if idLen > 256 {
		return 0, ErrNameTooLong
	}
	written := int64(0)
	n, err := w.Write([]byte{byte(blockSize), byte(name.Type), byte(idLen)})
	written += int64(n)
	if err != nil {
		return written, err
	}
	n, err = w.Write([]byte(name.Label))
	written += int64(n)
	if err != nil {
		return written, err
	}
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
func (name *Name) ReadFrom(r io.Reader) (int64, error) {
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

	err = binary.Read(r, binary.BigEndian, &name.Type)
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
	name.Label = builder.String()

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

	if chunkLen > 512 || chunkLen < 4 {
		return bytesRead, fmt.Errorf("invalid IDChunk length %d", chunkLen)
	}
	if paddingLen > chunkLen-4 {
		return bytesRead, fmt.Errorf("invalid IDChunk padding length %d (IDChunk only %d)", paddingLen, chunkLen)
	}

	blockLen := chunkLen - paddingLen - 4
	var blockBytesRead int64
	for blockBytesRead < int64(blockLen) {
		name := Name{}
		n, err := name.ReadFrom(r)
		blockBytesRead += n
		bytesRead += n
		if err != nil {
			return bytesRead, err
		}
		chunk.Blocks = append(chunk.Blocks, name)
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

func ReadCertificatePEM(b []byte) (*Certificate, error) {
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("could not decode PEM block")
	}
	buf := bytes.NewBuffer(p.Bytes)
	c := new(Certificate)
	_, err := c.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func ReadCertificatePEMFile(path string) (*Certificate, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	b, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}
	return ReadCertificatePEM(b)
}

func (c *Certificate) ProvideKey(private *[KeyLen]byte) error {
	switch c.Type {
	case Leaf:
		keyPair := keys.X25519KeyPair{
			Private: *private,
		}
		keyPair.PublicFromPrivate()
		if !bytes.Equal(c.PublicKey[:], keyPair.Public[:]) {
			return errors.New("mismatched public and private key")
		}
	case Intermediate, Root:
		keyPair := keys.SigningKeyPair{
			Private: *private,
		}
		keyPair.PublicFromPrivate()
		if !bytes.Equal(c.PublicKey[:], keyPair.Public[:]) {
			return errors.New("mismatched public and private key")
		}
	default:
		logrus.Panicf("unknown cert type: %d", c.Type)
	}
	c.privateKey = private
	return nil
}
