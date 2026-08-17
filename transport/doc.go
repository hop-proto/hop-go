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
// the session mutex. Receive loops use DeadlineChan.TrySend while holding the
// session mutex, so a full application queue drops a packet instead of blocking
// lifecycle progress. SessionState.closeLocked is the sole session-close
// transition and owns closing the receive queue to unblock all readers.
//
// State and lifecycle mutexes never span channel waits, wait-group waits, queue
// admission, or socket I/O. The checkblockinglocks command run by make vet
// enforces these known blocking-operation boundaries.
package transport
