// Package congestion is copied from github.com/quic-go/quic-go/internal/congestion.
// with slight modifications for compatibility
package congestion

import (
	"time"
)

// A SendAlgorithm performs congestion control
type SendAlgorithm interface {
	TimeUntilSend(bytesInFlight int64) time.Time
	HasPacingBudget(now time.Time) bool
	OnPacketSent(sentTime time.Time, bytesInFlight int64, packetNumber int64, bytes int64, isRetransmittable bool)
	CanSend(bytesInFlight int64) bool
	MaybeExitSlowStart()
	OnPacketAcked(number int64, ackedBytes int64, priorInFlight int64, eventTime time.Time)
	OnCongestionEvent(number int64, lostBytes int64, priorInFlight int64)
	OnRetransmissionTimeout(packetsRetransmitted bool)
	SetMaxDatagramSize(int64)
}

type SendAlgorithmWithDebugInfos interface {
	SendAlgorithm
	InSlowStart() bool
	InRecovery() bool
	GetCongestionWindow() int64
}
