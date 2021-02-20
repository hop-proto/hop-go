package portal

import "net"

// Client directly implements net.Conn
var _ net.Conn = &Client{}
