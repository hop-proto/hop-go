package tubes

import (
	"errors"
)

// ErrOutOfTubes indicates that the muxer has no more tubeIDs to assign
var ErrOutOfTubes = errors.New("out of tube IDs")

// ErrMuxerStopping indiates a new tube cannot be created because Muxer.Stop() has been called
var ErrMuxerStopping = errors.New("muxer is stopping")

// ErrBadTubeState indicates an operation was performed when a tube was in a state where that operation is not valid
var ErrBadTubeState = errors.New("tube in bad state")

// maximum number of packet an unreliable tube will buffer
const maxBufferedPackets = 1000
