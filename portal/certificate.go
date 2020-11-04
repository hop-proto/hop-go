package portal

// This is a temporary hack to just get static keys in the protocol
// TODO(dadrian): Implement certificate structure for real
type Certificate struct {
	Public []byte
	key    *X25519KeyPair
}

// TODO(dadrian): Length checks
func (c *Certificate) serialize(dst []byte) (int, error) {
	if c.key != nil {
		return copy(dst, c.key.public[:]), nil
	} else {
		return copy(dst, c.Public), nil
	}
}
