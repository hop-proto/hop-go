# Transport Concurrency Model and Close() Semantics

This document explains how the transport package achieves safe concurrent
operations on both client and server sides, and how `Close()` is correctly
serialized without races.

## 1. Concurrency Goals

- Allow separate goroutines to call `Read` and `Write` concurrently on the same connection.
- Ensure `Close` blocks until all background goroutines exit, and only one caller performs teardown.
- Permit buffered data to be delivered after `Close`, while new writes fail with `io.EOF`.
- Support concurrent calls to `SetDeadline` and related methods without interfering with pending operations.

## 2. Per-Connection `Handle`

- Defined in `transport/handle.go`: manages incoming messages via a buffered `DeadlineChan`, protected by a mutex.
- `ReadMsg` and `WriteMsg` lock around channel operations and `SessionState` writes, ensuring no data races (see lines around L55–87, L163–175).
- `Handle.Close()` acquires the session mutex, closes the receive channel (`recv.Close()`), and calls `SessionState.closeLocked()` to mark the handle closed (L179–185).

## 3. Client-Side Concurrency

- The `Client` struct (transport/client.go L41–58) uses three `sync.WaitGroup`s and an atomic `state` to track Created→Handshaking→Open→Closing→Closed.
- After handshake, `Client.listen()` runs in a goroutine until `state` changes, reading UDP packets and forwarding them to the handle (L328–342).
- `Client.Close()` uses atomic CAS to enter the Closing state, signals the listener via a read deadline, waits for the listener to exit, then closes the transport handle and underlying UDP socket (L476–510).

## 4. Server-Side Concurrency

- `Server.Serve()` (transport/server.go L494–546) launches two loops: a packet-read loop and a cookie-rotation loop, each gated on the server state, then waits for both to finish.
- `Server.Close()` (L676–733) uses an atomic CAS and `closeWait` to serialize multiple calls, unblocks the Serve loops via deadlines and channels, closes the pending-connections channel, drains and closes all session handles, and finally closes the UDP socket.

## 5. Why `Close()` Is Concurrent-Safe

- **Atomic state machine + waitgroups** protect against races and ensure single teardown.
- **Deadlines and channel closes** explicitly wake background loops and unblocks acceptors/readers.
- **Mutexes around session and handle state** prevent concurrent writes to shared state.

Together, these patterns fulfill the transport layer's concurrency goals and guarantee that `Close()` can be called safely from multiple goroutines without leaking resources or encountering data races.
