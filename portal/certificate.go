package portal

// Certificate currently contains a single static key pair. This is a hack to
// get static keys into the protocol. The full certificate is defined in the
// specification.
//
// TODO(dadrian): Implement certificate structure from the specification.
type Certificate struct {
	Public []byte
	key    *X25519KeyPair
}

// TODO(dadrian): Length checks
func (c *Certificate) serialize(dst []byte) (int, error) {
	if c.key != nil {
		return copy(dst, c.key.public[:]), nil
	}
	return copy(dst, c.Public), nil
}
