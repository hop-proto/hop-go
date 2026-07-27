// Package tubes multiplexes raw data into logical channels of a Hop session.
//
// # Concurrency model
//
// A Muxer owns one receiver and one sender goroutine. Its mutex protects the
// tube maps and elects the first Stop caller as the shutdown owner; later calls
// wait for the stopped channel, whose close publishes the cached results.
//
// Each Reliable's lifecycle mutex serializes state-machine transitions. Its
// sender has a separate mutex for acknowledgements and retransmission state;
// when both are needed, the Reliable mutex is acquired first. State transitions
// release these locks before waiting on another goroutine or doing socket I/O.
//
// Shutdown proceeds from producers to consumers. Tubes close and drain their
// sender queues before the Muxer closes its queues; the Muxer sender then drains
// those queues before the underlying connection is closed to stop the receiver.
// This ordering ensures that the final reliable FIN acknowledgement is normally
// written and that no goroutine can send on a closed queue. A bounded shutdown
// timer closes the connection if a transport write is stuck.
package tubes
