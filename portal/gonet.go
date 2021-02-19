package portal

import "net"

var _ net.Conn = &Client{}
