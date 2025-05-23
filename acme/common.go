package acme

import (
	"encoding/binary"
	"io"

	"hop.computer/hop/certs"
)

const ChallengeLen int = 32

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
