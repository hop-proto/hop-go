package portforwarding

import (
	"encoding/binary"
	"errors"
	"github.com/sirupsen/logrus"
	"hop.computer/hop/proxy"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"hop.computer/hop/common"
	"hop.computer/hop/tubes"
)

const (
	pfTCP  = 1
	pfUDP  = 2
	pfUNIX = 3
)

type FwdType byte

// TODO(drebelsky): We may be able to use net.addr eventually, but for now this works

type Addr struct {
	netType FwdType
	addr    string
}
type Forward struct {
	listen  Addr
	connect Addr
}
type FwdMapping struct {
	inbound  map[Addr]Addr
	im       sync.Mutex
	outbound map[Addr]Addr
	om       sync.Mutex
}

func NewFwdMapping() *FwdMapping {
	return &FwdMapping{
		inbound:  make(map[Addr]Addr),
		outbound: make(map[Addr]Addr),
	}
}

const (
	failure = 0
	success = 1
)

func readPacket(r io.Reader) (*Addr, error) {
	b := make([]byte, 1)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}

	pfType := FwdType(b[0])
	var hostLen uint16
	err = binary.Read(r, binary.BigEndian, &hostLen)
	if err != nil {
		return nil, err
	}

	host := make([]byte, hostLen)
	_, err = io.ReadFull(r, host)
	logrus.Debugf("PF: remote host address %v", string(host))
	if err != nil {
		return nil, err
	}

	return &Addr{
		pfType,
		string(host),
	}, nil
}
func toBytes(f *Addr) []byte {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(f.addr)))
	var res []byte
	res = append(res, byte(f.netType))
	res = append(res, length...)
	res = append(res, []byte(f.addr)...)
	return res
}

// notify when true indicates that the receiver doesn't need to start listening
// when false it should
func readFlags(r io.Reader) (start, notify bool, err error) {
	b := make([]byte, 1)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return
	}
	start = b[0]&1 != 0
	notify = b[0]&2 != 0
	return
}
func writeFlags(w io.Writer, start, notify bool) (err error) {
	b := make([]byte, 1)
	if start {
		b[0] |= 1
	}
	if notify {
		b[0] |= 2
	}
	_, err = w.Write(b)
	return err
}

// TODO (paul): unused, can be removed
func ClientLocalPF(local, remote *Addr, muxer *tubes.Muxer) {
	// only supports tcp right now
	ln, err := net.Listen("tcp", local.addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()

		if err != nil {
			log.Fatal(err)
		}

		tube, err := muxer.CreateReliableTube(common.PFTube)
		if err != nil {
			log.Fatal(err)
		}

		tube.Write(toBytes(remote))

		go func() {
			io.Copy(conn, tube)
			conn.Close()
		}()
		go func() {
			io.Copy(tube, conn)
			tube.Close()
		}()
	}
}

func StartPF(ch *tubes.Reliable, forward *Forward) {

	/*
		remote, err := readPacket(ch)
		if nil != remote {
			logrus.Debugf("paul this is the remote address, %v", remote.addr)
		}
		if err != nil {
			ch.Write([]byte{failure})
			ch.Close()
			return
		}

	*/

	local, err := readPacket(ch)

	if err != nil {
		ch.Write([]byte{failure})
		ch.Close()
		return
	}

	// This Dial is for creating a communication between the hop server(/client)
	// and the service that needs to be reached
	throwaway, err := net.Dial("tcp", local.addr)
	if err != nil {
		logrus.Error("PF: couldn't connect to local addr: ", err)
		ch.Write([]byte{failure})
		ch.Close()
		return
	}

	logrus.Debugf("PF: dialed address, %v", local.addr)
	throwaway.Close()

	forward.connect = *local

	ch.Write([]byte{success})
	return
}

// HanlePF is a function server side to dial the remote service
// and proxy it to the reliable tube initiated by the client
func HandlePF(ch *tubes.Reliable, forward *Forward) {
	conn, err := net.Dial("tcp", forward.connect.addr)
	if err != nil {
		logrus.Error("PF: couldn't connect to local addr: ", err)
		ch.Close() // Close the channel on error
		return
	}

	// TODO (paul): close properly the connection
	//defer conn.Close()

	go func() {
		// TODO (paul): close the connection
		// defer ch.Close()

		if err := proxy.ReliableProxy(conn, ch); err != nil {
			logrus.Errorf("PF: error in proxying: %v", err)
		}
	}()
}

// InitiatePFClient is initiated by the client on client session start.
// it writes the addr to dial for the remote server and send it through
// a control tube to ask the server to acknowledge
func InitiatePFClient(remoteFwds *Forward, muxer *tubes.Muxer) {

	pfControlTube, err := muxer.CreateReliableTube(common.PFControlTube)
	if err != nil {
		logrus.Error(err)
		return
	}

	// TODO (paul) close the connection
	//defer pfControlTube.Close()

	byteAddr := toBytes(&remoteFwds.connect)
	length := len(byteAddr)
	b := make([]byte, length)
	copy(b, byteAddr)

	_, err = pfControlTube.Write(b)
	if err != nil {
		log.Fatal(err)
	}

	n, err := pfControlTube.Read(b)
	if err != nil {
		return
	}
	logrus.Debugf("PF: Client receive this message %x", b[:n])

	// ClientHandlePF receive the server response from the PF control tube and start a new listener
	// with the local address and for as many connection that he needs, it will create and forward to
	// a new reliable PFtube. The listener is in TCP, then the tube is in reliable mode, otherwise, we
	// have to implement a unreliable tube for tcp addresses

	listener, err := net.Listen("tcp", remoteFwds.listen.addr)
	if err != nil {
		log.Fatal(err)
	}
	// TODO (paul): close the connection
	//defer listener.Close()

	reliableProxyTube, err := muxer.CreateReliableTube(common.PFTube)
	if err != nil {
		logrus.Errorf("PF: error making reliable PF tube with : %v", err)
		return
	}

	// TODO (paul): close the connection
	//defer reliableProxyTube.Close()

	for {
		local, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		logrus.Infof("Connection accepted from %s", local.RemoteAddr())
		go func(conn net.Conn) {
			// TODO (paul) close the connection
			//defer conn.Close()
			proxy.ReliableProxy(conn, reliableProxyTube)
		}(local)
	}

}

// TODO (paul) this function is not used, can be removed
func clientStartLocalPF(local *Addr, remote *Addr) {
	listener, err := net.Listen("tcp", local.addr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	for {
		// Like ssh -L by default, local connections are handled one at a time.
		// While one local connection is active in runTunnel, others will be stuck
		// dialing, waiting for this Accept.
		_, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		// Issue a dial to the remote server on our SSH client; here "localhost"
		// refers to the remote server.
		/*
			tube, err := muxer.CreateReliableTube(common.PFTube)
			if err != nil {
				log.Fatal(err)
			}
			runTunnel(ln, rt)

		*/
		// TODO (paul) check why this tunnel is called 10 times
		//fmt.Println("tunnel established with", local.addr)
	}
}

// ErrInvalidPortForwardingArgs returned when client receives unsupported -L or -R options
var ErrInvalidPortForwardingArgs = errors.New("port forwarding currently only supported with port:host:hostport format")

// ErrInvalidPFArgs is returned when there is a problem parsing portfowarding argument
var ErrInvalidPFArgs = errors.New("error parsing portforwarding argument")

// Fwd holds state related to portforwarding parsed from cmdline or config
type Fwd struct {
	Listensock        bool   // true if listening on a socket (not a host, port pair)
	Connectsock       bool   // true if destination is a socket
	Listenhost        string // optional bind address on listening peer
	Listenportorpath  string // port to listen on or socket to listen on
	Connecthost       string // optional final destination (not used if final dest is a socket)
	Connectportorpath string // final dest port or socket path
}

// returns true if a forward slash exists
func checkPath(arg string) bool {
	return strings.Contains(arg, "/")
}

/*-R port (ssh acts as a SOCKS 4/5 proxy) HOP NOT SUPPORTED -R
A. (3) -R port:host:hostport or 				-L port:host:hostport 				--> listen_port:connect_host:connect_port (3 no sock)
B. (2) -R port:local_socket or 					-L port:remote_socket 				--> listen_port:connect_socket				(1 no sock)

C. (4) -R bind_address:port:host:hostport or 	-L bind_address:port:host:hostport 	--> listen_address:listen_port:connect_host:connect_port (4 no sock)
D. (3) -R bind_address:port:local_socket or 	-L bind_address:port:remote_socket 	--> listen_address:listen_port:connect_socket (2 no sock)

E. (3) -R remote_socket:host:hostport or 		-L local_socket:host:hostport 		--> listen_socket:connect_host:connect_port (2 no sock)
F. (2) -R remote_socket:local_socket or 		-L local_socket:remote_socket 		--> listen_socket:connect_socket (0 no sock)

*/

// Bind address meanings
//o  "" means that connections are to be accepted on all protocol
// families supported by the SSH implementation.

// o  "0.0.0.0" means to listen on all IPv4 addresses.

// o  "::" means to listen on all IPv6 addresses.

// o  "localhost" means to listen on all protocol families supported by
// the SSH implementation on loopback addresses only ([RFC3330] and
// [RFC3513]).

// o  "127.0.0.1" and "::1" indicate listening on the loopback
// interfaces for IPv4 and IPv6, respectively.

/*
ParseForward takes in a PF argument and populates fwdStruct with data
if Remote: listen is on the remote peer (hop server) and connect is contacted by the local peer
if Local: listen is on the local peer (hop client) and connect is contacted by the remote peer
[listenhost:]listenport|listenpath:connecthost:connectport|connectpath
  - listenpath:connectpath
*/
func ParseForward(arg string) (forward *Forward, err error) {
	loopback := "127.0.0.1"
	//TODO: expand env vars
	//skip leading/trailing whitespace
	arg = strings.TrimSpace(arg)
	parts := []string{}

	nleft := strings.Count(arg, "[")
	nright := strings.Count(arg, "]")
	if nleft > 2 || nleft != nright {
		return nil, ErrInvalidPFArgs
	}
	// 1 bracketed address (first)
	// 1 bracketed address (middle)
	// both bracketed addresses

	//at least 1 bracketed expression
	if strings.Index(arg, "[") == 0 {
		logrus.Info("first brackets found")
		//first address is IPv6
		end := strings.Index(arg, "]")
		logrus.Info("end is: ", end)
		if end <= 0 {
			logrus.Error("end less than or eq to 0")
			return nil, ErrInvalidPFArgs
		}
		parts = append(parts, arg[1:end])
		if arg[end+1] != ':' { //must be followed by a colon to have a port number at a minimum
			logrus.Errorf("next char is not a colon: %v", arg)
			return nil, ErrInvalidPFArgs
		}
		arg = arg[end+2:] //skip past trailing colon
	}
	if strings.Contains(arg, "[") {
		logrus.Info("second brackets found")
		start := strings.Index(arg, "[")
		end := strings.Index(arg, "]")
		if end <= start {
			return nil, ErrInvalidPFArgs
		}
		if start > 0 {
			//check colon right before it
			if arg[start-1] != ':' { //must be preceded by a colon
				return nil, ErrInvalidPFArgs
			}
			rawParts := strings.Split(arg[:start-1], ":")
			parts = append(parts, rawParts...)
		}
		parts = append(parts, arg[start+1:end])
		if arg[end+1] != ':' { //must be followed by a colon to have a port number at a minimum
			return nil, ErrInvalidPFArgs
		}
		arg = arg[end+2:] //skip past trailing colon
	}
	//split and append whatever is left to parts
	rawParts := strings.Split(arg, ":")
	parts = append(parts, rawParts...)

	if len(parts) < 2 {
		return forward, ErrInvalidPFArgs
	}

	forward = &Forward{}
	forward.listen.netType = pfTCP
	forward.connect.netType = pfTCP

	if checkPath(parts[0]) {
		forward.listen.addr = parts[0]
		forward.listen.netType = pfUNIX
		parts = parts[1:]
	}
	if checkPath(parts[len(parts)-1]) {
		forward.listen.addr = parts[len(parts)-1]
		forward.listen.netType = pfUNIX
		parts = parts[:len(parts)-1]
	}
	switch len(parts) {
	case 0: //both listen and connect were sockets
		return forward, err
	case 1: // all that remains is listen_port (connect_socket already parsed)
		//listen_port:connect_socket				(1 no netType)
		forward.listen.addr = loopback + ":" + parts[0]

	case 2: // listen or connect was a socket. 2 args remain
		if forward.connect.netType == pfTCP {
			forward.connect.addr = parts[0] + ":" + parts[1]
		} else if forward.listen.netType == pfTCP {
			forward.listen.addr = parts[0] + ":" + parts[1]
		}
	case 3: //listen_port:connect_host:connect_port (3 no netType)
		forward.listen.addr = loopback + ":" + parts[0]
		forward.connect.addr = parts[1] + ":" + parts[2]
	case 4: //listen_address:listen_port:connect_host:connect_port (4 no netType)
		forward.listen.addr = parts[0] + ":" + parts[1]
		forward.connect.addr = parts[2] + ":" + parts[3]
	default:
		return forward, ErrInvalidPFArgs
	}

	return forward, err
}
