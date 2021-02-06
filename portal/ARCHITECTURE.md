Architecture
============

TODO

### Notes

- The server-side implementation needs to multiplex multiple connections
- Each connection should be able to read and write independently


#### Concurrency

- Each connection should safely allow calls to `Read` and `Write` from separate threads.
- Close should block until it is safely closed
- Buffered data can be returned after a `Close`.
- All calls to `Write` should fail after a close.
- Calls to `SetDeadline`, `SetTimeout`, et. all should be allowed to be called from multiple threads, and should not affect pending calls (\todo is this right?)
