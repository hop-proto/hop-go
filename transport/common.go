package transport

import (
	"errors"

	"golang.org/x/crypto/curve25519"

	"zmap.io/portal/kravatte"
)

// ProtocolName is the string representation of the parameters used in this version
const ProtocolName = "hop_NN_XX_cyclist_keccak_p1600_12"

// Version is the protocol version being used. Only one version is supported.
const Version byte = 0x01

// Protocol size constants
const (
	HeaderLen = 4
	MacLen    = 16
	// TODO(dadrian): It's confusing to have MacLen and TagLen
	TagLen       = 32
	KeyLen       = 16
	DHLen        = curve25519.PointSize
	CookieLen    = DHLen + kravatte.TagSize
	SNILen       = 256
	SessionIDLen = 4
	CounterLen   = 8
)

// MaxTotalPacketSize is MaxUDPPacketSize minus bytes used by Ethernet frames and Wifi frames.
//
// TODO(dadrian): Verify this size, this is definitely too small
const MaxTotalPacketSize = 65535 - 1000

// MaxPlaintextSize is MaxTotalPacketSize minus bytes used by transport messages
const MaxPlaintextSize = MaxTotalPacketSize - HeaderLen - SessionIDLen - CounterLen - MacLen

// Derived protocol size constants
const (
	HelloLen          = HeaderLen + DHLen + MacLen
	AssociatedDataLen = HeaderLen + SessionIDLen + CounterLen
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

// ErrUnknownMessage is returned when a mess contains an unknown MessageType in
// byte 0.
var ErrUnknownMessage = errors.New("unknown message type")

// ErrWouldBlock is returned when an operation would need to block to finish.
var ErrWouldBlock = errors.New("operation would block")

// ErrTimeout is returned for operations that timed out
var ErrTimeout = errors.New("operation timed out")

// ErrReplay is returned when a message is a duplicate. This should not
// percolate outside of the internal APIs.
var ErrReplay = errors.New("packet is a replay")

// MessageType is a single-byte-wide enum used as the first byte of every message. It can be used to differentiate message types.
type MessageType byte

// MessageType constants for each type of handshake and transport message.
const (
	MessageTypeClientHello MessageType = 0x01
	MessageTypeServerHello MessageType = 0x02
	MessageTypeClientAck   MessageType = 0x03
	MessageTypeServerAuth  MessageType = 0x04
	MessageTypeClientAuth  MessageType = 0x05
	MessageTypeTransport   MessageType = 0x10
)

// IsHandshakeType returns true if the message type is part of the handshake, not the transport.
func (mt MessageType) IsHandshakeType() bool { return (byte(mt) & byte(0x0F)) != 0 }
