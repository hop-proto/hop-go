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

	KeyPair *keys.X25519KeyPair // TODO(dadrian): Abstract to just the DH interface
	Leaf    *certs.Certificate  // TODO(dadrian): Do we eve need this field?
}
