package portal

type HandshakeMessage struct {
	HeaderWord [4]byte
	Body       []byte // This might not work because the length might not be known without parsing?
}

type ClientHello struct {
	Ephemeral []byte
}

func (m *ClientHello) serialize(b []byte) (int, error) {
	if len(b) < 4+len(m.Ephemeral) {
		return 0, ErrBufFull
	}
	// Type = ClientHello (0x01)
	b[0] = 0x01
	b[1] = Version
	// Reserved
	b[2] = 0
	b[3] = 0
	// Ephemeral
	n := copy(b[4:], m.Ephemeral)
	if n != len(m.Ephemeral) {
		return 0, ErrBufFull
	}
	return 4 + n, nil
}

type ServerHello struct {
}
