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

	HostName string
}
