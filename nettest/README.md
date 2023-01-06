# About

This is a custom fork of the Golang nettests with functionality for testing unreliable connections.
You can find the original source code here [https://cs.opensource.google/go/x/net/+/master:nettest/](https://cs.opensource.google/go/x/net/+/master:nettest/).

## Files Changes

- `conntest.go`
- `conntest_test.go`

## Changes

- In conntest.go, `MakePipe` has been modified so that it takes a `*testing.T` as an argument.
This testing context can be used for additional logging.

- `MakePipe` also returns an additional boolean that indicates if the connection is reliable or not.
For unreliable connections, like UDP, the `BasicIO` test is skipped since unreliable connections do not pass it.

