#  Remote Port Forwarding
## Current Hop Support
- -R port:host:hostport

### TODOs:
- improve robustness of abstract socket address names (currently tied to remote port)
- provide support for sockets instead of ports like ssh
- provide support for bind address
- clearer conf/den and error messages
- add originator information like ssh (?)

### General Flow (from SSH)
1. Server allocates a socket to listen to TCP port on loopback interface (on remote side)
2. Whenever a connection is made to this port, the connection is forwarded through the Hop session back to the local machine.
3. The local machine makes a connection to host:hostport and forwards traffic

### Hop Implementation Flow
1. User specifies >= 1 -R flag when starting hop client
2. For each -R flag the hop client starts a reliable tube with the server and sends the arg across
3. On the server side, the server checks that the client is authorized to do this action
4. If authorized, server prepares to start child process that will actually bind to the port by starting 2 unix domain sockets. One of them is to convey control information to the child process (so it can be killed when the hop session ends) the other is to actually move data from the child process to the server process (and thus over a tube back to the local side)
5. If both of the sockets are started successfully then the server starts a child process with user level privileges.
6. The child process binds to 127.0.0.1:port (loopback address and specified remote port) and connects to the control socket with the server (when the child connects to the control socket the server interprets this as indication that binding to the socket was successful). If an error occurs when binding, then the child process connects to the content socket and sends a Denial message.
7. If the binding is successful then the server sends a confirmation back to the client
8. The child process listens for incoming tcp connections, accepts them, and connects to the content socket. Forwards the connection until it hits EOF and then closes content socket connection.
9. The server makes a new tube back to the local side and sends across the arg corresponding to that RPF relationship (i.e. port:host:hostport) so that the client can check that it actually asked for such a connection and so it knows where to forward the data to. TODO: SSH also sends the originator IP/port should hop do this?
10. Local side checks that it asked for this RPF (arg matches one of it's requested) and then establishes a TCP connection to host:hostport. 

## OpenSSH parsing code for portforwarding flags: https://github.com/openssh/openssh-portable/blob/master/readconf.c#L2880

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
socket, the connection is forwarded over the secure channel (from RFC4254: "When
a connection comes to a port for which remote forwarding has been requested, a
channel is opened to forward the port to the other side."), and a connection is
made from the local machine to either an explicit destination specified by host
port hostport, or local_socket, or, if no explicit destination was specified,
ssh will act as a SOCKS 4/5 proxy and forward connections to the destinations
requested by the remote SOCKS client.

Port forwardings can also be specified in the configuration file.  Privileged
ports can be forwarded only when logging in as root on the remote machine.  IPv6
addresses can be specified by enclosing the address in square brackets.

By default, TCP listening sockets on the server will be bound to the loopback
interface only.  This may be overridden by specifying a bind_address.  An empty
bind_address, or the address ‘*’, indicates that the remote socket should listen
on all interfaces.  Specifying a remote bind_address will only succeed if the
server's GatewayPorts option is enabled (see sshd_config(5)).

If the port argument is ‘0’, the listen port will be dynamically allocated on
the server and reported to the client at run time.  When used together with -O
forward the allocated port will be printed to the standard output.


# Local Port Forwarding
## Current Hop Support
- -L port:host:hostport
### TODOs:

### General Flow:
1. Client listens to a local TCP port or Unix socket
2. When it receives a connection it sends it over hop session to the remote side
3. The remote side establishes a connection to the end destination and forwards the connection to there

### Hop Implementation Flow
1. User specifies >= 1 -L flags when starting hop client
2. For each -L flag the hop client starts listening on the local port. (port)
6. When the client receives a connection it establishes a new tube to the server and sends over the arg
8. The server checks authorization
9. If authorized the server establishes a connection to the end destination and forwards the connection to it. (host:hostport)

## SSH doc on -L option
- -L [bind_address:]port:host:hostport
- -L [bind_address:]port:remote_socket
- -L local_socket:host:hostport
- -L local_socket:remote_socket

Specifies that connections to the given TCP port or Unix socket on the local
(client) host are to be forwarded to the given host and port, or Unix socket, on
the remote side.  This works by allocating a socket to listen to either a TCP
port on the local side, optionally bound to the specified bind_address, or to a
Unix socket.  Whenever a connection is made to the local port or socket, the
connection is forwarded over the secure channel, and a connection is made to
either host port hostport, or the Unix socket remote_socket, from the remote
machine.

Port forwardings can also be specified in the configuration file.  Only the
superuser can forward privi‐ leged ports.  IPv6 addresses can be specified by
enclosing the address in square brackets.

By default, the local port is bound in accordance with the GatewayPorts setting.
However, an explicit bind_address may be used to bind the connection to a
specific address.  The bind_address of “localhost” indicates that the listening
port be bound for local use only, while an empty address or ‘*’ indicates that
the port should be available from all interfaces.

# Dynamic Port Forwarding

## TODO: Implement

- -D [bind_address:]port

Specifies a local “dynamic” application-level port forwarding.  This works by
allocating a socket to listen to port on the local side, optionally bound to the
specified bind_address.  Whenever a connection is made to this port, the
connection is forwarded over the secure channel, and the application protocol is
then used to determine where to connect to from the remote machine.  Currently
the SOCKS4 and SOCKS5 protocols are supported, and ssh will act as a SOCKS
server.  Only root can forward privileged ports. Dynamic port forwardings can
also be specified in the configuration file.

IPv6 addresses can be specified by enclosing the address in square brackets.
Only the superuser can forward privileged ports.  By default, the local port is
bound in accordance with the GatewayPorts set‐ ting.  However, an explicit
bind_address may be used to bind the connection to a specific address.  The
bind_address of “localhost” indicates that the listening port be bound for local
use only, while an empty address or ‘*’ indicates that the port should be
available from all interfaces.