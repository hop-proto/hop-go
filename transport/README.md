# Hop Transport Layer

## Notes

- The server-side implementation needs to multiplex multiple Hop connections on
  a single UDP socket.
- Each connection should be able to read and write independently
- Packet processing is not the same thing as stream processing! This is why
  most interactions with the `transport` layer should be through the `MsgConn`
  interface.

## Concurrency Goals

- Each connection should safely allow calls to `Read` and `Write` from separate threads.
- Close should block until it is safely closed
- Buffered data can be returned after a `Close`.
- All calls to `Write` should fail after a close.
- Calls to `SetDeadline` et. all should be allowed to be called from multiple
  threads, and should not affect pending calls.

In theory, we want this package to be able to pass the tests in
[nettest](https://pkg.go.dev/golang.org/x/net/nettest#TestConn).

