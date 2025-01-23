// Package protocol has been adapted from github.com/quic-go/quic-go/internal/protocol.
// It exports types and constants used in the congestion package (which is also adapted from quic-go)
package protocol

import "time"

type ByteCount int64
type PacketNumber int64

// TODO(hosono) documentation

// InitialPacketSize is the initial (before Path MTU discovery) maximum packet size used.
const InitialPacketSize = 1200

const InvalidPacketNumber PacketNumber = -1

// MaxCongestionWindowPackets is the maximum congestion window in packet.
const MaxCongestionWindowPackets = 10000

const MaxByteCount = ByteCount(1<<62 - 1)

// MinPacingDelay is the minimum duration that is used for packet pacing
// If the packet packing frequency is higher, multiple packets might be sent at once.
// Example: For a packet pacing delay of 200μs, we would send 5 packets at once, wait for 1ms, and so forth.
const MinPacingDelay = time.Millisecond

// TimerGranularity is the smallest value that the loss detection timer can be set to.
const TimerGranularity = time.Millisecond
