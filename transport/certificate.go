package transport

import "zmap.io/portal/keys"

// Certificate currently contains a single static key pair. This is a hack to
// get static keys into the protocol. The full certificate is defined in the
// specification.
//
// TODO(dadrian): Implement certificate structure from the specification.
type Certificate struct {
	Public []byte
	key    *keys.X25519KeyPair
}

// TODO(dadrian): Length checks
func (c *Certificate) serialize(dst []byte) (int, error) {
	if c.key != nil {
		return copy(dst, c.key.Public[:]), nil
	}
	return copy(dst, c.Public), nil
}
