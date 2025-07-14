// Package certs defines the Hop certificates structure, including serialization
// and verification functions.
package certs

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"

	"hop.computer/hop/keys"
)

// Byte-length constants for cryptographic material
const (
	KeyLen       = 32
	KemKeyLen    = 800 // ML-KEM 512 PublicKey size
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
	PQLeaf       CertificateType = 4
)

// String implements Stringer for CertificateType.
func (t CertificateType) String() string {
	switch t {
	case Leaf:
		return "leaf"
	case Intermediate:
		return "intermediate"
	case Root:
		return "root"
	case PQLeaf:
		return "pqleaf"
	default:
		return "unknown"
	}
}

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
	case "pqleaf":
		return PQLeaf, nil
	default:
		return 0, fmt.Errorf("unknown certificate type: %s", typeStr)
	}
}

const (
	// SHA3Len is the length of a SHA256Fingerprint array
	SHA3Len = 32

	// Version is the protocol version
	Version byte = 1
)

// SHA3Fingerprint is used to identify the parent of a Certificate.
type SHA3Fingerprint = [SHA3Len]byte

var zero SHA3Fingerprint
var zeroSignature [SignatureLen]byte

// Certificate represent a Hop certificate, and can be serialized to and from
// bytes. A Certificate can optionally be associated with its corresponding
// private key.
type Certificate struct {
	Version   byte
	Type      CertificateType
	IssuedAt  time.Time
	ExpiresAt time.Time
	IDChunk   IDChunk
	PublicKey []byte
	Parent    SHA3Fingerprint
	Signature [SignatureLen]byte

	// Fingerprint is the 256-bit SHA3 of the certificate. It is populated when
	// a certificate is read, or issued.
	Fingerprint SHA3Fingerprint

	privateKey *[KeyLen]byte

	raw bytes.Buffer
}

// IDType indicates the type of an identifier label, e.g. DNSName, IPAddress, etc.
type IDType byte

// Known IDType values
const (
	TypeRaw         IDType = 0x00
	TypeDNSName     IDType = 0x01
	TypeIPv4Address IDType = 0x02
	TypeIPv6Address IDType = 0x03
)

// Name is a UTF-8 label and an IDType. It can be encoded to an IDBlock.
type Name struct {
	Label []byte
	Type  IDType
}

// String converts a Name into a human readable string
func (name *Name) String() string {
	switch name.Type {
	case TypeDNSName:
		return string(name.Label)
	case TypeIPv4Address, TypeIPv6Address:
		return net.IP(name.Label).String()
	case TypeRaw:
		if utf8.Valid(name.Label) {
			return string(name.Label)
		} else {
			return fmt.Sprintf("%x", name.Label)
		}
	default:
		panic(fmt.Sprintf("unexpected certs.IDType: %#v", name.Type))
	}
}

// DNSName returns a Name with Type set to TypeDNSName and the provided label.
func DNSName(label string) Name {
	return Name{
		Label: []byte(label),
		Type:  TypeDNSName,
	}
}

// RawStringName returns a Name with Type set to TypeRaw and the label set to
// the UTF-8 encoded string. It is useful for creating names where the meaning is interpreted from a string, but that do not represent a DNSName.
func RawStringName(label string) Name {
	return Name{
		Label: []byte(label),
		Type:  TypeRaw,
	}
}

// IsZero returns true if the label is empty and tye type is 0.
func (name Name) IsZero() bool {
	// When Label is []byte{} (0-length, non-nil), it does not count as zero.
	// It's an explicitly empty, raw name.
	return name.Label == nil && name.Type == 0
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

	chunkLen, err := c.IDChunk.WriteTo(w)
	written += chunkLen
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

// Marshal writes a serialized certificate to newly-allocated memory.
func (c *Certificate) Marshal() ([]byte, error) {
	buf := bytes.Buffer{}
	_, err := c.WriteTo(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReadFrom populates a certificate from serialized bytes.
func (c *Certificate) ReadFrom(r io.Reader) (int64, error) {
	var bytesRead int64
	var err error

	// Save the bytes
	c.raw.Reset()
	tee := io.TeeReader(r, &c.raw)

	// Calculate hash as we read
	h := sha3.New256()
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

	publicKeyLen := KeyLen

	if c.Type == PQLeaf {
		publicKeyLen = KemKeyLen
	}
	buf := make([]byte, publicKeyLen)
	n, err := io.ReadFull(r, buf)
	c.PublicKey = buf

	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}

	if n != publicKeyLen {
		return bytesRead, io.EOF
	}

	n, err = io.ReadFull(r, c.Parent[:])
	bytesRead += int64(n)
	if err != nil {
		return bytesRead, err
	}
	if n != SHA3Len {
		return bytesRead, io.EOF
	}

	chunkLen, err := c.IDChunk.ReadFrom(r)
	bytesRead += chunkLen
	if err != nil {
		return bytesRead, err
	}

	n, err = io.ReadFull(r, c.Signature[:])
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

// SerializedLen returns the length of this IDChunk if it were to be serialized.
// It does not serialize the IDChunk.
func (chunk *IDChunk) SerializedLen() int {
	outputLen := 2
	for i := range chunk.Blocks {
		blockSize := chunk.Blocks[i].BlockSize()
		outputLen += blockSize
	}
	return outputLen
}

// BlockSize returns the length of this block when serialized, and how many
// bytes of the serialization are padding. The padding is included in the block
// size.
func (name *Name) BlockSize() int {
	return len(name.Label) + 3
}

// WriteTo serializes the IDBlock to w.
func (name *Name) WriteTo(w io.Writer) (int64, error) {
	blockSize := name.BlockSize()
	if blockSize > 256 {
		return 0, ErrNameTooLong
	}
	idLen := len(name.Label)
	if idLen > 256-3 {
		return 0, ErrNameTooLong
	}
	written := int64(0)
	n, err := w.Write([]byte{byte(blockSize), byte(name.Type), byte(idLen)})
	written += int64(n)
	if err != nil {
		return written, err
	}
	n, err = w.Write(name.Label)
	written += int64(n)
	if err != nil {
		return written, err
	}
	return written, nil
}

// ReadFrom reads a serialized IDBlock from r.
func (name *Name) ReadFrom(r io.Reader) (int64, error) {
	var bytesRead int64

	var encodedBlockSize byte
	err := binary.Read(r, binary.BigEndian, &encodedBlockSize)
	if err != nil {
		return bytesRead, err
	}
	bytesRead++
	blockSize := int(encodedBlockSize)
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

	if int(serverIDLen) > blockSize-3 {
		return bytesRead, fmt.Errorf("invalid server ID len %d (max for block size %d is %d)", serverIDLen, blockSize, blockSize-3)
	}

	// TODO(dadrian): Maybe IDBlock should store an []byte, then we can avoid
	// this allocation.
	// TODO(dadrian): This shouldn't be a string builder, not that the labels
	// aren't immediately converted to strings.
	builder := strings.Builder{}
	copied, err := io.CopyN(&builder, r, int64(serverIDLen))
	bytesRead += copied
	if err != nil {
		return bytesRead, err
	}
	name.Label = []byte(builder.String())

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

	if chunkLen > 512 || chunkLen < 2 {
		return bytesRead, fmt.Errorf("invalid IDChunk length %d", chunkLen)
	}

	blockLen := chunkLen - 2
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

	for i := range chunk.Blocks {
		n, err := chunk.Blocks[i].WriteTo(w)
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// PEMTypeHopCertificate is the header string used for PEM files for Hop certificates.
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

// ReadCertificatePEM reads the first PEM-encoded bytes in b as a Certificate.
// It will only read a single PEM. To read many PEMs, use ReadFrom and the
// encoding/pem module directly.
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

// ReadCertificatePEMFileFS reads the first PEM-encoded certificate from a PEM file.
func ReadCertificatePEMFileFS(path string, fs fs.FS) (*Certificate, error) {
	if fs == nil {
		return ReadCertificatePEMFile(path)
	}
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return ReadCertificatePEM(b)
}

// ReadCertificatePEMFile reads the first PEM-encoded certificate from a PEM file.
func ReadCertificatePEMFile(path string) (*Certificate, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	b, err := io.ReadAll(fd)
	if err != nil {
		return nil, err
	}
	return ReadCertificatePEM(b)
}

// ReadCertificateBytesFromPEMFile reads the first PEM-encoded certificate from
// a PEM file, and additionally returns the bytes corresponding to the
// certificate.
func ReadCertificateBytesFromPEMFile(path string) (*Certificate, []byte, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer fd.Close()
	b, err := io.ReadAll(fd)
	if err != nil {
		return nil, nil, err
	}
	return ReadCertificateBytesPEM(b)
}

// ReadCertificateBytesPEM reads the first PEM-encoded bytes in b as a
// Certificate. It will only read a single PEM. It returns certificate, and a
// slice of the bytes parsed.
func ReadCertificateBytesPEM(b []byte) (*Certificate, []byte, error) {
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, nil, errors.New("could not decode PEM block")
	}
	buf := bytes.NewBuffer(p.Bytes)
	c := new(Certificate)
	_, err := c.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}
	return c, p.Bytes, nil
}

// ProvideKey sets the private key associated with the public key in the
// certificate. You must call ProvideKey before calling any issue functions with
// this certificate.
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

// ScannerSplitPEM is a bufio.SplitFunc that breaks input into chunks that can be handled by pem.Decode()
func ScannerSplitPEM(data []byte, atEOF bool) (int, []byte, error) {
	block, rest := pem.Decode(data)
	if block != nil {
		size := len(data) - len(rest)
		return size, data[:size], nil
	}
	return 0, nil, nil
}

// ReadManyCertificatesPEM reads a stream of concatenated PEM-encoded Hop
// certificates. PEMs that are not Hop certificates are ignored, as is non-PEM
// data.
func ReadManyCertificatesPEM(r io.Reader) ([]Certificate, error) {
	scanner := bufio.NewScanner(r)
	scanner.Split(ScannerSplitPEM)
	scanner.Buffer(nil, 1024*64)
	var out []Certificate
	for scanner.Scan() {
		p, _ := pem.Decode(scanner.Bytes())
		if p == nil {
			continue
		}
		if p.Type != PEMTypeHopCertificate {
			continue
		}
		c := Certificate{}
		n, err := c.ReadFrom(bytes.NewBuffer(p.Bytes))
		if err != nil {
			return nil, err
		}
		if int(n) != len(p.Bytes) {
			return nil, errors.New("extra bytes after certificate")
		}
		out = append(out, c)
	}
	return out, nil
}
