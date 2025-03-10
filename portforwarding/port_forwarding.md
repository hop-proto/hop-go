# Resources
## OpenSSH parsing code for portforwarding flags: https://github.com/openssh/openssh-portable/blob/master/readconf.c#L2880
## https://datatracker.ietf.org/doc/html/rfc4254#section-7

### TODOs:
- (Security) Check permission and segmentation for PF on sockets
- Add a visual message to the user when PF is failing (same as delegate
  dialogues)
- Add configurability to enable unreliable tubes for UNIX sockets and TCP
- Implement multiple port forwarding (several -R/-L flags)

#  Remote Port Forwarding
## Current Hop Support
- (-udp) -R listen_port:connect_host:connect_port
- (-udp) -R listen_address:listen_port:connect_host:connect_port
- (-udp) -R listen_port:[2001:db8::1]:connect_port 
- (-udp) -R [2001:db8:3333:4444:5555:6666:7777:8888]:listen_port:[2001:db8::1]:connect_port
- -R listen_port:/connect_socket
- -R /listen_socket:/connect_socket
- -R listen_address:listen_port:/connect_socket
- -R /listen_socket:connect_host:connect_port
- -R [2001:db8::1]:listen_port:/connect_socket

### TODOs:


### General Flow (from SSH)
1. Server allocates a socket to listen to TCP/UDP (or the specified UNIX socket)
   on loopback interface (on remote side)
2. Whenever a connection is made to this port, the connection is forwarded
   through the Hop session in a PFTube back to the local machine.
3. The local machine makes a connection to host:hostport and forwards traffic

### Hop Implementation Flow

1. The user specifies the -R flag when starting the hop client
2. The hop client establishes a reliable tube with the server and transmits 
   the listen address via the PFControlTube.
3. On the server side, the server verifies whether the client is authorized 
   to perform this action.
4. If authorized, the server starts listening on the specified address 
   provided by the client.
5. Whenever the server receives an incoming connection on its listener:
   - A reliable tube is created for TCP and UNIX socket connections. 
   - A best-effort (unreliable) tube is created for UDP connections.
6. The server establishes a proxy between the newly accepted connection 
   and the corresponding tube, forwarding all traffic between them.
7. On the client side:
    - The client dials the target address and, upon a successful connection,
    - It creates a proxy between the received tube and the new connection.
    - A new proxy is instantiated for each received tube.
8. If either connection endpoint encounters an EOF, timeout, or other errors,
   the closure is propagated across all related connections, ensuring that 
   the listener connection, client connection, and PFTube are properly closed.



## SSH doc on -R option
- -R [bind_address:]port:host:hostport
- -R [bind_address:]port:local_socket
- -R remote_socket:host:hostport
- -R remote_socket:local_socket
- -R [bind_address:]port

Specifies that connections to the given TCP port or Unix socket on the remote
(server) host are to be forwarded to the local side.

This works by allocating a socket to listen to either a TCP port or to a Unix
socket on the remote side. Whenever a connection is made to this port or Unix
socket, the connection is forwarded over the secure channel (from RFC4254:
"When a connection comes to a port for which remote forwarding has been
requested, a channel is opened to forward the port to the other side."), and a
connection is made from the local machine to either an explicit destination
specified by host port hostport, or local_socket, or, if no explicit
destination was specified, ssh will act as a SOCKS 4/5 proxy and forward
connections to the destinations requested by the remote SOCKS client.

Port forwardings can also be specified in the configuration file.  Privileged
ports can be forwarded only when logging in as root on the remote machine.
IPv6 addresses can be specified by enclosing the address in square brackets.

By default, TCP listening sockets on the server will be bound to the loopback
interface only.  This may be overridden by specifying a bind_address.  An empty
bind_address, or the address ‘*’, indicates that the remote socket should
listen on all interfaces.  Specifying a remote bind_address will only succeed
if the server's GatewayPorts option is enabled (see sshd_config(5)).

If the port argument is ‘0’, the listen port will be dynamically allocated on
the server and reported to the client at run time.  When used together with -O
forward the allocated port will be printed to the standard output.


# Local Port Forwarding
## Current Hop Support
- (-udp) -L listen_port:connect_host:connect_port
- (-udp) -L listen_address:listen_port:connect_host:connect_port
- (-udp) -L listen_port:[2001:db8::1]:connect_port
- (-udp) -L [2001:db8:3333:4444:5555:6666:7777:8888]:listen_port:[2001:db8::1]:connect_port
- -L listen_port:/connect_socket
- -L /listen_socket:/connect_socket
- -L listen_address:listen_port:/connect_socket
- -L /listen_socket:connect_host:connect_port
- -L [2001:db8::1]:listen_port:/connect_socket

### TODOs:

### General Flow:
1. Client listens to a local TCP/UDP port or Unix socket
2. When it receives a connection it sends it over hop session to the remote
   side
3. The remote side establishes a connection to the end destination and forwards
   the connection to there

### Hop Implementation Flow
1. The user specifies the -L flag when starting the hop client.
2. The client starts listening on the specified local address and send
   the connect address through a PFControlTube.
3. On the server side, the server verifies whether the client is authorized
   to perform this action.
4. If authorized, the server will dial the connect address and if the 
   connection succeeds, the server respond with a success message.
5. Whenever the client receives an incoming connection on this listener:
    - It establishes a reliable tube for TCP and UNIX socket connections.
    - It establishes a best-effort (unreliable) tube for UDP connections.
6. The client establishes a proxy between the accepted connection and the 
   corresponding tube, forwarding all traffic between them.
7. On the server side:
   - The server dials the connect address received earlier. 
   - It creates a proxy between the received tube and the new connection. 
   - A new proxy is instantiated for each received tube.

8. If either connection endpoint encounters an EOF, timeout, or other errors, 
   the closure is propagated across all related connections, ensuring that 
   the client listener connection, server connect connection, and PFTube are
   properly closed.

## SSH doc on -L option
- -L [bind_address:]port:host:hostport
- -L [bind_address:]port:remote_socket
- -L local_socket:host:hostport
- -L local_socket:remote_socket

Specifies that connections to the given TCP port or Unix socket on the local
(client) host are to be forwarded to the given host and port, or Unix socket,
on the remote side.  This works by allocating a socket to listen to either a
TCP port on the local side, optionally bound to the specified bind_address, or
to a Unix socket.  Whenever a connection is made to the local port or socket,
the connection is forwarded over the secure channel, and a connection is made
to either host port hostport, or the Unix socket remote_socket, from the remote
machine.

Port forwardings can also be specified in the configuration file.  Only the
superuser can forward privi‐ leged ports.  IPv6 addresses can be specified by
enclosing the address in square brackets.

By default, the local port is bound in accordance with the GatewayPorts
setting. However, an explicit bind_address may be used to bind the connection
to a specific address.  The bind_address of “localhost” indicates that the
listening port be bound for local use only, while an empty address or ‘*’
indicates that the port should be available from all interfaces.

# Dynamic Port Forwarding

## TODO: Implement

- -D [bind_address:]port

Specifies a local “dynamic” application-level port forwarding.  This works by
allocating a socket to listen to port on the local side, optionally bound to
the specified bind_address.  Whenever a connection is made to this port, the
connection is forwarded over the secure channel, and the application protocol
is then used to determine where to connect to from the remote machine.
Currently the SOCKS4 and SOCKS5 protocols are supported, and ssh will act as a
SOCKS server.  Only root can forward privileged ports. Dynamic port forwardings
can also be specified in the configuration file.

IPv6 addresses can be specified by enclosing the address in square brackets.
Only the superuser can forward privileged ports.  By default, the local port is
bound in accordance with the GatewayPorts set‐ ting.  However, an explicit
bind_address may be used to bind the connection to a specific address.  The
bind_address of “localhost” indicates that the listening port be bound for
local use only, while an empty address or ‘*’ indicates that the port should be
available from all interfaces.