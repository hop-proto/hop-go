// Package congestion is adapted from quic-go, which is distributed under the MIT license
// see https://github.com/quic-go/quic-go
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
