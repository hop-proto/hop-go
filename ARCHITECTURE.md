Architecture
============

## File Structure

Each top-level folder should have its own README.

The other top-level folders are organized as follows:
- `cyclist`: Contains an implementation of the Cyclist duplex using specific
  parameters for Keccak
- `kravatte`: Contains an implementation of the Kravatte AEAD, with specific
  Keccak parameters.
- `snp`: Byte-manipulation code shared between Kravatte and Cyclist
- `transport`: Implementation of the $PROTOCOL transport-layer
- `reliable`: Proof-of-concept of $PROTOCOL channels.
- `channels`: Implementation of the $PROTCOL channels on top of the transport
  layer. Not yet started.

### Notes

- The server-side implementation needs to multiplex multiple connections
- Each connection should be able to read and write independently


#### Concurrency

- Each connection should safely allow calls to `Read` and `Write` from separate threads.
- Close should block until it is safely closed
- Buffered data can be returned after a `Close`.
- All calls to `Write` should fail after a close.
- Calls to `SetDeadline`, `SetTimeout`, et. all should be allowed to be called from multiple threads, and should not affect pending calls (\todo is this right?)
