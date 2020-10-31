package portal

// MessageType is a single-byte-wide enum used as the first byte of every message. It can be used to differentiate message types.
type MessageType byte

// MessageType constants for each type of handshake and transport message.
const (
	MessageTypeClientHello MessageType = 0x01
	MessageTypeServerHello             = 0x02
	MessageTypeClientAck               = 0x03
	MessageTypeServerAuth              = 0x04
	MessageTypeClientAuth              = 0x05
)

type HandshakeMessage struct {
	HeaderWord [4]byte
	Body       []byte // This might not work because the length might not be known without parsing?
}

type ClientHello struct {
	Ephemeral []byte
}

func (m *ClientHello) serialize(b []byte) (int, error) {
	if len(b) < 4+DHLen {
		return 0, ErrBufOverflow
	}
	if len(m.Ephemeral) != DHLen {
		return 0, ErrInvalidMessage
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
		return 0, ErrBufOverflow
	}
	return 4 + n, nil
}

func (m *ClientHello) deserialize(b []byte) (int, error) {
	if len(b) < HeaderLen+DHLen {
		return 0, ErrBufUnderflow
	}
	if MessageType(b[0]) != MessageTypeClientHello {
		return 0, ErrUnexpectedMessage
	}
	if b[1] != Version {
		return 0, ErrUnsupportedVersion
	}
	// TODO(dadrian): Should we check if reserved fields are zero?
	// TODO(dadrian): Avoid allocation?
	m.Ephemeral = make([]byte, DHLen)
	b = b[4:]
	copy(m.Ephemeral, b[:DHLen])
	b = b[DHLen:]
	return 4 + DHLen, nil
}

type ServerHello struct {
	Ephemeral []byte
	Cookie    []byte
}

func (m *ServerHello) serialize(b []byte) (int, error) {
	if len(b) < HeaderLen+DHLen+len(m.Cookie) {
		return 0, ErrBufOverflow
	}
	x := b
	x[0] = MessageTypeServerHello
	x[1] = 0
	x[2] = 0
	x[3] = 0
	x = x[4:]
	n := copy(x[0:DHLen], m.Ephemeral)
	if n != DHLen {
		return 0, ErrInvalidMessage
	}
	x = x[DHLen:]
	n = copy(x, m.Cookie)
	if n != len(m.Cookie) {
		return 0, ErrBufOverflow
	}
	return 4 + DHLen + n, nil
}

func (m *ServerHello) deserialize(b []byte) (int, error) {
	if len(b) < HeaderLen+DHLen+CookieLen {
		return 0, ErrBufOverflow
	}
	x := b
	if MessageType(x[0]) != MessageTypeServerHello {
		return 0, ErrUnexpectedMessage
	}
	x = b[4:]
	// TODO(dadrian): Should we check if reserved fields are zero?
	m.Ephemeral = make([]byte, DHLen)
	n := copy(m.Ephemeral, x[:DHLen])
	if n != DHLen {
		return 0, ErrInvalidMessage
	}
	x = x[DHLen:]
	m.Cookie = make([]byte, CookieLen)
	n = copy(m.Cookie, x[:CookieLen])
	if n != CookieLen {
		return 0, ErrInvalidMessage
	}
	return 4 + DHLen + CookieLen, nil
}

type ClientAck struct {
}
