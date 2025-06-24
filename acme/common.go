package acme

import (
	"encoding/binary"
	"fmt"
	"io"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

const ChallengeLen int = 32
const AcmeUser = "reserved_hop_certificate_request_username"

// TODO(hosono) maybe this should be signed?
type DomainNameAndKey struct {
	DomainName string
	PublicKey  [certs.KeyLen]byte
}

func (d *DomainNameAndKey) Write(w io.Writer) (int, error) {
	buf := make([]byte, len(d.DomainName)+len(d.PublicKey)+2)
	binary.BigEndian.PutUint16(buf, uint16(len(d.DomainName)))
	copy(buf[2:], []byte(d.DomainName))
	copy(buf[2+len(d.DomainName):], d.PublicKey[:])

	return w.Write(buf)
}

func (d *DomainNameAndKey) Read(r io.Reader) error {
	var domainLen uint16
	err := binary.Read(r, binary.BigEndian, &domainLen)
	if err != nil {
		return err
	}

	domainBuf := make([]byte, int(domainLen))
	io.ReadFull(r, domainBuf)

	d.DomainName = string(domainBuf)
	_, err = io.ReadFull(r, d.PublicKey[:])

	return err
}

type CertificateRequest struct {
	// TODO additional certificate request info
	Name   certs.Name
	PubKey keys.PublicKey
}

func (req *CertificateRequest) WriteTo(w io.Writer) (int64, error) {
	if req.Name.Type != certs.TypeDNSName {
		return 0, fmt.Errorf("only DNS names are currently supported")
	}

	n, err := req.Name.WriteTo(w)
	if err != nil {
		return n, err
	}

	n2, err := w.Write(req.PubKey[:])
	return int64(n2) + n, err
}

func (req *CertificateRequest) ReadFrom(r io.Reader) (int64, error) {
	n, err := req.Name.ReadFrom(r)
	if err != nil {
		return n, err
	}

	n2, err := io.ReadFull(r, req.PubKey[:])
	return int64(n2) + n, err
}
