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
// when both are needed, the Reliable mutex is acquired first. Closing releases
// the lifecycle mutex while waiting for the tube sender to drain, and actual
// socket I/O belongs solely to the Muxer sender.
//
// Shutdown proceeds from producers to consumers. Tubes close and drain their
// sender queues before the Muxer closes its queues. The Muxer sender then gets a
// bounded drain period before the underlying connection is closed to stop the
// receiver. This ordering normally writes the final reliable FIN acknowledgement
// and ensures no goroutine can send on a closed queue; the bound prevents a stuck
// transport write from deadlocking shutdown.
package tubes
