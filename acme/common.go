// Package acme contains structs and methods to run acme servers and clients
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

// DomainNameAndKey is a message requesting a certificate for a given domain name and public key
// TODO(hosono) maybe this should be signed?
type DomainNameAndKey struct {
	DomainName string
	Port       uint16
	PublicKey  [certs.KeyLen]byte
}

func (d *DomainNameAndKey) Write(w io.Writer) (int, error) {
	buf := make([]byte, len(d.DomainName)+len(d.PublicKey)+4)
	binary.BigEndian.PutUint16(buf, uint16(len(d.DomainName)))
	copy(buf[2:], []byte(d.DomainName))
	binary.BigEndian.PutUint16(buf[2+len(d.DomainName):], d.Port)
	copy(buf[4+len(d.DomainName):], d.PublicKey[:])

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
	err = binary.Read(r, binary.BigEndian, &d.Port)
	if err != nil {
		return err
	}
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

// Generates a fully self-signed chain for the given key pair
func createCertChain(domainName string, ourKeys *keys.X25519KeyPair) (root, intermediate, leaf *certs.Certificate, err error) {
	rootKeys := keys.GenerateNewSigningKeyPair()
	rootCert, err := certs.SelfSignRoot(certs.SigningIdentity(rootKeys), rootKeys)
	if err != nil {
		return nil, nil, nil, err
	}
	err = rootCert.ProvideKey((*[32]byte)(&rootKeys.Private))
	if err != nil {
		return nil, nil, nil, err
	}

	intermediateKeys := keys.GenerateNewSigningKeyPair()
	intermediateCert, err := certs.IssueIntermediate(rootCert, certs.SigningIdentity(intermediateKeys))
	if err != nil {
		return nil, nil, nil, err
	}
	err = intermediateCert.ProvideKey((*[32]byte)(&intermediateKeys.Private))
	if err != nil {
		return nil, nil, nil, err
	}

	leafCert, err := certs.IssueLeaf(intermediateCert, certs.LeafIdentity(ourKeys, certs.DNSName(domainName)))
	if err != nil {
		return nil, nil, nil, err
	}

	return rootCert, intermediateCert, leafCert, nil
}
