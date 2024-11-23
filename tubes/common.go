package tubes

import (
	"errors"
	"time"
)

// ErrOutOfTubes indicates that the muxer has no more tubeIDs to assign
var ErrOutOfTubes = errors.New("out of tube IDs")

// ErrMuxerStopping indiates a new tube cannot be created because Muxer.Stop() has been called
var ErrMuxerStopping = errors.New("muxer is stopping")

// ErrBadTubeState indicates an operation was performed when a tube was in a state where that operation is not valid
var ErrBadTubeState = errors.New("tube in bad state")

var errFrameOutOfBounds = errors.New("received data frame out of receive window bounds")

// TODO(hosono) create a config struct to pass to the muxer to set these things

// MaxFrameDataLength is the maximum bytes per frame in a Reliable or Unreliable tube
// TODO(hosono) IPv4 is only required to support packets up to 576 bytes long,
// but usually internet routers can support much larger packets.
// Correctly implementing MTU discovery is complicated. Setting this to a
// value that is always safe (~500), leads to unacceptable performance loss.
// Setting this a large value may cause unreliable tubes to intermittently fail.
const MaxFrameDataLength uint16 = 32768

// maximum number of packet an unreliable tube will buffer
const maxBufferedPackets = 1000

// amount of time before retransmitting packets
// TODO(hosono) implement RTT measurements to dynamically adjust this
const retransmitOffset = 100 * time.Millisecond

// the number of packets in the window for reliable tubes
const windowSize uint64 = 1 << 18

// TODO(hosono) choose this time
// amount of time to wait for all all tubes to close when muxer is stopping
const muxerTimeout = time.Second
