package netproxy

import (
	"io"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/tubes"
)

/*
-L [bind_address:]port:host:hostport
     -L [bind_address:]port:remote_socket
     -L local_socket:host:hostport
     -L local_socket:remote_socket
             Specifies that connections to the given TCP port or Unix socket on the local (client) host are to be
             forwarded to the given host and port, or Unix socket, on the remote side.  This works by allocating a
             socket to listen to either a TCP port on the local side, optionally bound to the specified bind_address,
             or to a Unix socket.  Whenever a connection is made to the local port or socket, the connection is for‐
             warded over the secure channel, and a connection is made to either host port hostport, or the Unix
             socket remote_socket, from the remote machine.

             Port forwardings can also be specified in the configuration file.  Only the superuser can forward privi‐
             leged ports.  IPv6 addresses can be specified by enclosing the address in square brackets.

             By default, the local port is bound in accordance with the GatewayPorts setting.  However, an explicit
             bind_address may be used to bind the connection to a specific address.  The bind_address of “localhost”
             indicates that the listening port be bound for local use only, while an empty address or ‘*’ indicates
             that the port should be available from all interfaces.
*/

//LocalServer starts a TCP Conn with remote addr and proxies traffic from ch -> tcp and tcp -> ch
func LocalServer(npTube *tubes.Reliable, arg string) {
	//dest := fromBytes(init)
	//TODO: more flexible parsing of arg
	parts := strings.Split(arg, ":") //assuming port:host:hostport
	addr := net.JoinHostPort(parts[1], parts[2])
	if _, err := net.LookupAddr(addr); err != nil {
		//Couldn't resolve address with local resolver
		h, p, e := net.SplitHostPort(addr)
		if e != nil {
			logrus.Error(e)
			npTube.Write([]byte{NpcDen})
			return
		}
		if ip, ok := hostToIPAddr[h]; ok {
			addr = ip + ":" + p
		}
	}
	logrus.Infof("dialing dest: %v", addr)
	tconn, err := net.Dial("tcp", addr)
	if err != nil {
		logrus.Errorf("C: error dialing server: %v", err)
		npTube.Write([]byte{NpcDen})
		return
	}
	defer tconn.Close()
	logrus.Info("connected to: ", arg)
	npTube.Write([]byte{NpcConf})
	logrus.Infof("wrote confirmation that NPC ready")
	//could net.Pipe() be useful here?
	go func() {
		//Handles all traffic from principal to server 2
		io.Copy(tconn, npTube)
	}()
	//handles all traffic from server 2 back to principal
	io.Copy(npTube, tconn)
}
