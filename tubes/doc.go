// Package tubes multiplexes raw data into logical channels of a Hop session.
//
// # Concurrency model
//
// A Muxer owns one transport receiver and one transport sender goroutine. The
// sender is the only reader of the Muxer's two raw outbound queues and the only
// writer to the underlying transport. Tubes submit frames through the Muxer's
// cancellable outbox; they cannot access or close either raw queue. The queues
// are never closed. Separate stop and abort channels prevent send-on-closed
// races and wake both normal and priority admissions on failure. A distinct
// stopping broadcast wakes Accept and remote-tube queue admission immediately;
// stopped remains the completion publication for concurrent Stop callers.
//
// Lifecycle and state mutexes protect only bounded in-memory transitions. Code
// must not hold one while waiting on a channel, wait group, queue admission, or
// socket operation. Cancellation is therefore always publishable by Close or
// Stop, including with GOMAXPROCS=1. The checkblockinglocks command, run by
// make vet, mechanically enforces known blocking operations in tubes and
// transport.
//
// Reliable state transitions reserve frames while locked and admit them only
// after unlocking. Its local wake channels are owned and closed by Reliable;
// the final FIN acknowledgement is reserved before terminal sender cancellation
// and admitted before close completion. Unreliable uses DeadlineChan as its
// bounded local queue: Close rejects writers and cancels blocked Send calls,
// then the sole sender drains accepted data and admits FIN last.
//
// Shutdown proceeds from producers to consumers. Tubes reject new work and join
// their producers before Muxer requests sender stop. A transport write failure
// aborts the outbox before starting Stop, immediately waking both admission
// priorities. A bounded fallback closes the underlying transport to interrupt a
// stuck write; completion channels publish cached results to concurrent callers.
package tubes
