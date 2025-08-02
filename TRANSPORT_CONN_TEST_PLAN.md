# Transport Conn Abstraction Test Plan

This test plan describes how to test the core connection (`MsgConn`/`net.Conn`) abstractions provided by the `transport/` package, focusing on post-handshake behavior, concurrency, and connection closing semantics.

Refer to the concurrency goals outlined in the `transport/README.md` for context:
[Concurrency Goals](transport/README.md#concurrency-goals)【F:transport/README.md†L12-L19】

## Objectives

- Verify that after a successful handshake, the `MsgConn` abstraction functions according to its specification.
- Ensure that concurrent reads and writes are safe and behave correctly without data races or deadlocks.
- Validate connection closing semantics: blocking behavior, buffered data flushing, and error conditions after close.
- Test deadline and timeout behavior under concurrent operations.

## Scope

- Post-handshake behavior of `Client`, `Handle`, and `UDPMsgConn` implementations.
- Interaction of `ReadMsg`, `WriteMsg`, `Read`, `Write`, `Close`, and deadline methods (`SetDeadline`, `SetReadDeadline`, `SetWriteDeadline`).
- Edge cases around closing connections during in-flight operations.

## Test Environment Setup

1. Establish a client and a server performing a cryptographic handshake over UDP using loopback endpoints.
2. Confirm handshake completion before executing post-handshake tests.
3. Use controlled goroutines and synchronization (channels, wait groups) to orchestrate concurrent actions and observe timings.

## Test Cases

### 1. Concurrent Read and Write

- **Description**: Verify that calling `ReadMsg` and `WriteMsg` concurrently on the same connection does not cause races or deadlocks.
- **Steps**:
  1. Start a goroutine performing continuous `WriteMsg` calls.
  2. Start a goroutine performing continuous `ReadMsg` calls.
  3. Run both for a fixed duration or a fixed number of messages.
- **Expected**: No data races (verified via `go test -race`), no panics, and message integrity maintained.

### 2. Deadline Interaction under Concurrency

- **Description**: Ensure that deadlines can be set concurrently without affecting pending I/O calls.
- **Steps**:
  1. Launch read and write operations that block indefinitely (e.g., waiting for data).
  2. Concurrently call `SetDeadline`, `SetReadDeadline`, and `SetWriteDeadline` multiple times.
  3. Observe that existing blocked calls eventually return errors only due to deadline expiration, not deadlock.
- **Expected**: Deadlines trigger appropriate timeout errors; setting deadlines does not leak goroutines or prevent I/O from returning.

### 3. Close Unblocks In-Flight Operations

- **Description**: Verify that calling `Close` on a connection unblocks any in-flight `ReadMsg`, `Read`, `WriteMsg`, or `Write` calls.
- **Steps**:
  1. Start a goroutine blocking on `ReadMsg` (or `Read`).
  2. Start a goroutine blocking on `WriteMsg` (or `Write`) by providing no remote peer.
  3. Invoke `Close` from the main goroutine.
  4. Wait for blocked operations to return.
- **Expected**: All blocked calls return promptly with an error indicating the connection is closed.

### 4. Buffered Data Returned After Close

- **Description**: Confirm that `ReadMsg`/`Read` can return buffered data even after `Close` is called.
- **Steps**:
  1. Have the peer send a few messages and ensure they are queued locally.
  2. Call `Close` on the local connection.
  3. Consume queued messages with `ReadMsg`/`Read` until empty.
  4. Verify subsequent reads return `io.EOF` or an appropriate closed error.
- **Expected**: Buffered messages are delivered; after exhaustion, reads return EOF.

### 5. Write Fails After Close

- **Description**: Ensure that any `WriteMsg`/`Write` performed after `Close` immediately returns an error.
- **Steps**:
  1. Call `Close` on the connection.
  2. Attempt to send new messages.
- **Expected**: Writes return a "use of closed network connection" or equivalent error.

### 6. Idempotent Close

- **Description**: Validate that multiple calls to `Close` do not cause panics or additional errors.
- **Steps**:
  1. Call `Close` on the connection once.
  2. Call `Close` again.
- **Expected**: Subsequent `Close` calls return a consistent error or nil and do not panic.

### 7. Peer-Initiated Close

- **Description**: Test behavior when the remote endpoint closes the connection.
- **Steps**:
  1. After handshake, have the peer call `Close`.
  2. Perform `ReadMsg`/`Read` and `WriteMsg`/`Write` on the other side.
- **Expected**: Reads return EOF or closed error; writes return closed connection error.

### 8. Race Between Close and Deadline or I/O

- **Description**: Stress race conditions by invoking `Close`, deadline changes, and I/O in rapid succession.
- **Steps**:
  1. Spawn multiple goroutines each randomly choosing to `ReadMsg`, `WriteMsg`, set deadlines, or `Close`.
  2. Run for a short duration under the race detector.
- **Expected**: No data races, deadlocks, or unexpected panics.

### 9. Stress Test Under High Concurrency

- **Description**: Subject the connection to high-volume, concurrent reads, writes, deadlines, and closes to uncover subtle races.
- **Steps**:
  1. Use a large number of goroutines performing random operations (`ReadMsg`, `WriteMsg`, `SetDeadline`, `Close`).
  2. Run under `go test -race` with sufficient iterations.
- **Expected**: Stability under load with correct semantics.

## Metrics and Verification

- Use `go test -race` to catch data races.
- Measure operation latency and ensure `Close` latency remains bounded.
- Track goroutine count to detect leaks in tests.

---
*Document generated as part of planning for improving and hardening the `transport` package.*
