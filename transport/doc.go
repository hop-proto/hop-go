// Package transport implements the Hop Transport Protocol.
//
// # Concurrency model
//
// Client and Server lifecycle state is atomic: a successful state transition
// elects one goroutine to perform an operation, while later callers wait on a
// completion channel. Results are stored before that channel is closed, so its
// close both broadcasts completion and publishes the results to every waiter.
//
// Wait groups count only goroutines that have already been started. A Server's
// lifecycle lock makes registering a Serve call atomic with Close, and the
// lifecycle owner closes the underlying connection before waiting so blocked
// I/O cannot prevent shutdown.
//
// A SessionState mutex protects session lifecycle, counters, and cryptographic
// state. Handle's read and write locks serialize their respective operations.
// Packet state is updated while locked, but socket I/O happens after releasing
// the session mutex. SessionState.closeLocked is the sole session-close
// transition and closes the receive queue to unblock all readers.
package transport
