package portal

import (
	"errors"

	"golang.org/x/crypto/curve25519"
)

// MaxTotalPacketSize is MaxUDPPacketSize minus bytes used by Ethernet frames and Wifi frames.
//
// TODO(dadrian): Verify this size
const MaxTotalPacketSize = 65535 - 18

// ProtocolName is the string representation of the parameters used in this version
const ProtocolName = "noise_NN_XX_cyclist_keccak_p1600_12"

// Version is the protocol version being used. Only one version is supported.
const Version byte = 0x01

// Protocol size constants
const (
	HeaderLen    = 4
	MacLen       = 16
	KeyLen       = 16
	DHLen        = curve25519.PointSize
	CookieLen    = 32 + 16 + 12
	SNILen       = 256
	SessionIDLen = 4
	CounterLen   = 8
)

// Derived protocol size constants
const (
	HelloLen = HeaderLen + DHLen + MacLen
)

// ErrBufOverflow is returned when write would go off the end off a buffer.
var ErrBufOverflow = errors.New("write would overflow buffer")

// ErrBufUnderflow is returned when a read would go past the end of a buffer.
var ErrBufUnderflow = errors.New("read would be past end of buffer")

// ErrUnexpectedMessage is returned when the wrong message is received during
// the handshake, or when a handshake message is received after completing the
// handshake.
var ErrUnexpectedMessage = errors.New("attempted to deserialize unexpected message type")

// ErrUnsupportedVersion is returned when the version field in a handshake
// packet is anything besides Version.
var ErrUnsupportedVersion = errors.New("unsupported version")

// ErrInvalidMessage is returned when a message is serialized or otherwise created incorrectly.
var ErrInvalidMessage = errors.New("invalid message")

// ErrUnknownSession is returned when a message contains an unknown SessionID.
var ErrUnknownSession = errors.New("unknown session")
