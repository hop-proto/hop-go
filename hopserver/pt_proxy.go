package hopserver

// PT Proxy: Server acts as a proxy between the Principal client
// and Target server.

// Delegate proxy server: a hop server that has an active hop session with
// a (remote) Principal hop client and a (local) Delegate hop client that was
// started from a process spawned from that active hop session. Two "proxying"
// actions actually occur:
// 1. Delegate hop client <--> Principal hop client (dp_proxy.go)
// 2. Principal hop client <--> Target hop server (pt_proxy.go) (*)

// Responsibilities [status] (2: Principal <--> Target proxy):
// - run a "UDP proxy" between the Principal (unreliable tube) and Target
// 	(udp "conn") (roughly implemented)
// - only create a proxy if it is expected and allowed (partially implemented)
// - close down the proxy/associated resources neatly if either side fails (TODO)
