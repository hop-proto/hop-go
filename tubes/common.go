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

// This error is used to let the muxer retry Accept calls if it get a tube that cannot be given to the caller
var errGotKeepAlive = errors.New("accepted keep alive tube. this tube is not passed to the caller")

// TODO(hosono) create a config struct to pass to the muxer to set these things

// MaxFrameDataLength is the maximum bytes per frame in a Reliable or Unreliable tube
const MaxFrameDataLength uint16 = 2000

// maximum number of packet an unreliable tube will buffer
const maxBufferedPackets = 1000

// amount of time before retransmitting packets
const retransmitOffset = 500 * time.Millisecond

// the maximum number of packets to retransmit per rto
// even if the window is larger, no more packets will be transmitted
const maxFragTransPerRTO = 50

// the number of packets in the window for reliable tubes
const windowSize = 128

// TODO(hosono) choose this time
// amount of time to linger in the timeWait state when closing
const timeWaitTime = 3 * time.Second

// TODO(hosono) choose this time
// amount of time to wait for all all tubes to close when muxer is stopping
const muxerTimeout = 2 * timeWaitTime
