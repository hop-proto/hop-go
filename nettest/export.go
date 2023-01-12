package nettest

// This file export several method from conntest.go
// so that we can run individual tests without running all of the TestConn.
// Specifically, these are used to run the BasicIO test on Reliable Tubes when some packets are dropped.

// TimeoutWrapper exports timeoutWrapper
var TimeoutWrapper = timeoutWrapper

// BasicIO export testBasicIO
var BasicIO = testBasicIO
