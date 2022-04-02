package transport

import (
	"zmap.io/portal/certs"
	"zmap.io/portal/keys"
)

// Certificate holds a certs.Certificate from the perspective of a server
// instance.
type Certificate struct {
	RawLeaf         []byte
	RawIntermediate []byte

	Exchanger keys.Exchangable
	Leaf      *certs.Certificate // TODO(dadrian): Do we eve need this field?
}
