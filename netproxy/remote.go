package netproxy

/*
SSH doc on -R option
-R [bind_address:]port:host:hostport
     -R [bind_address:]port:local_socket
     -R remote_socket:host:hostport
     -R [bind_address:]port:local_socket
     -R remote_socket:host:hostport
     -R remote_socket:local_socket
     -R [bind_address:]port
             Specifies that connections to the given TCP port or Unix socket on the remote (server) host are to be
             forwarded to the local side.

             This works by allocating a socket to listen to either a TCP port or to a Unix socket on the remote side.
             Whenever a connection is made to this port or Unix socket, the connection is forwarded over the secure
             channel, and a connection is made from the local machine to either an explicit destination specified by
             host port hostport, or local_socket, or, if no explicit destina tion was specified, ssh will act as a
             SOCKS 4/5 proxy and forward connections to the destinations requested by the remote SOCKS client.

             Port forwardings can also be specified in the configuration file.  Privileged ports can be forwarded
             only when logging in as root on the remote machine.  IPv6 addresses can be specified by enclosing the
             address in square brackets.

             By default, TCP listening sockets on the server will be bound to the loopback interface only.  This may
             be overridden by specifying a bind_address.  An empty bind_address, or the address ‘*’, indicates that
             the remote socket should listen on all interfaces.  Specifying a remote bind_address will only succeed
             if the server's GatewayPorts option is enabled (see sshd_config(5)).

             If the port argument is ‘0’, the listen port will be dynamically allocated on the server and reported to
             the client at run time.  When used together with -O forward the allocated port will be printed to the
             standard output.
*/

const sock = "@remotesock"

//RemoteServer starts listening on given port and pipes the traffic back over the tube
// func RemoteServer(npTube *tubes.Reliable, arg string) {
// 	parts := strings.Split(arg, ":")                  //assuming port:host:hostport
// 	tcpListener, e := net.Listen("tcp", ":"+parts[0]) //TODO(baumanl): this runs with root privileges which is bad because unprivileged users can forward privileged ports on the server
// 	if e != nil {
// 		logrus.Error("Issue listening on requested port")
// 		npTube.Write([]byte{NpcDen})
// 		return
// 	}
// 	tconn, e := tcpListener.Accept() //TODO(baumanl): should this be in a loop? how does SSH do it?
// 	if e != nil {
// 		logrus.Error("Issue accepting conn on remote port")
// 		npTube.Write([]byte{NpcDen})
// 		return
// 	}
// 	npTube.Write([]byte{NpcConf})
// 	//could net.Pipe() be useful here?
// 	go func() {
// 		//Handles all traffic from principal to server 2
// 		io.Copy(tconn, npTube)
// 	}()
// 	//handles all traffic from server 2 back to principal
// 	io.Copy(npTube, tconn)
// }
