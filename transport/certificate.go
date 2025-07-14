package transport

import (
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

// Certificate holds a certs.Certificate from the perspective of a server
// instance.
type Certificate struct {
	RawLeaf         []byte
	RawIntermediate []byte

	Exchanger keys.Exchangable
	Leaf      *certs.Certificate // TODO(dadrian): Do we eve need this field?

	HostNames []string
}

func MakeCert(keyPair *keys.X25519KeyPair, leaf, intermdiate *certs.Certificate) (*Certificate, error) {
	leafBytes, err := leaf.Marshal()
	if err != nil {
		return nil, err
	}
	intermediateBytes, err := intermdiate.Marshal()
	if err != nil {
		return nil, err
	}

	return &Certificate{
		RawLeaf:         leafBytes,
		RawIntermediate: intermediateBytes,
		Exchanger:       keyPair,
		Leaf:            leaf,
		HostName:        "",
	}, nil
}
