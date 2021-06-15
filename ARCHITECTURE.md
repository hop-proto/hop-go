Architecture
============

Documentation of the code and types themselves should be primarily done in
comments following Golang conventions. This document explains where to go looking for specific things.

## File Structure

Each top-level folder should have its own README.

The other top-level folders are organized as follows:
- `cyclist`: Contains an implementation of the Cyclist duplex using specific
  parameters for Keccak
- `kravatte`: Contains an implementation of the Kravatte function and 
  DECK-SANSE AEAD, with specific Keccak parameters.
- `snp`: Byte-manipulation code shared between Kravatte and Cyclist
- `certs`: Tooling and parsing for the certificate format used by Hop
- `transport`: Implementation of the Hop transport-layer
- `reliable`: Proof-of-concept of Hop channels.
- `channels`: Production implementation of the Hop channels on top of the Hop
  transport layer.

### Notes

- The server-side implementation needs to multiplex multiple Hop connections on
  a single UDP socket.
- Each connection should be able to read and write independently
- Packet processing is not the same thing as stream processing! This is why
  most interactions with the `transport` layer should be through the `MsgConn`
  interface.

#### Concurrency

- Each connection should safely allow calls to `Read` and `Write` from separate threads.
- Close should block until it is safely closed
- Buffered data can be returned after a `Close`.
- All calls to `Write` should fail after a close.
- Calls to `SetDeadline` et. all should be allowed to be called from multiple threads, and should not affect pending calls.
