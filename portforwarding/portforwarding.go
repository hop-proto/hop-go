package portforwarding

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
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
	success = 0
	failure = 1
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

func listen(local, remote *Addr, table *FwdMapping, muxer *tubes.Muxer) bool {
	// only supports tcp right now
	ln, err := net.Listen("tcp", local.addr)
	if err != nil {
		return false
	}
	table.om.Lock()
	table.outbound[*local] = *remote
	table.om.Unlock()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				break
			}
			tube, err := muxer.CreateTube(common.PFTube)
			if err != nil {
				break
			}
			_, err = tube.Write(toBytes(local))
			if err != nil {
				tube.Close()
				break
			}
			_, err = tube.Write(toBytes(remote))
			if err != nil {
				tube.Close()
				break
			}
			// TODO: make nonblocking, but also figure out how to exit
			b := make([]byte, 1)
			_, err = io.ReadFull(tube, b)
			if err != nil {
				tube.Close()
				break
			}
			if b[0] != 0 {
				tube.Close()
				break
			}
			go func() {
				io.Copy(conn, tube)
				conn.Close()
			}()
			go func() {
				io.Copy(tube, conn)
				tube.Close()
			}()
		}
	}()
	return true
}

func HandleServerControl(ch *tubes.Reliable, table *FwdMapping, muxer *tubes.Muxer) {
	for {
		start, notify, err := readFlags(ch)
		if err != nil {
			break
		}
		remote, err := readPacket(ch)
		if err != nil {
			break
		}
		local, err := readPacket(ch)
		if err != nil {
			break
		}
		// TODO actually stop somehow
		if notify {
			// TODO: verify that this PF is okay
			table.im.Lock()
			table.inbound[*remote] = *local
			table.im.Unlock()
			ch.Write([]byte{success})
			continue
		}
		if start {
			if listen(local, remote, table, muxer) {
				ch.Write([]byte{success})
			} else {
				ch.Write([]byte{failure})
			}
		} else {
			status := byte(success)
			table.om.Lock()
			table.outbound[*local] = *remote
			listed, ok := table.outbound[*local]
			if ok && listed == *remote {
				delete(table.outbound, *local)
			} else {
				status = failure
			}
			table.om.Unlock()
			ch.Write([]byte{status})
		}
	}
}

func HandlePF(ch *tubes.Reliable, table *FwdMapping) {
	remote, err := readPacket(ch)
	_ = remote
	if err != nil {
		ch.Write([]byte{failure})
		ch.Close()
		return
	}
	local, err := readPacket(ch)
	if err != nil {
		ch.Write([]byte{failure})
		ch.Close()
		return
	}
	table.im.Lock()
	listed, ok := table.inbound[*remote]
	table.im.Unlock()
	if !ok || listed != *local {
		ch.Write([]byte{failure})
		ch.Close()
		return
	}

	conn, err := net.Dial("tcp", local.addr)
	if err != nil {
		ch.Write([]byte{failure})
		ch.Close()
		return
	}
	ch.Write([]byte{success})
	go func() {
		io.Copy(conn, ch)
		conn.Close()
	}()
	go func() {
		io.Copy(ch, conn)
		ch.Close()
	}()
}

func InitiatePF(ch *tubes.Reliable, table *FwdMapping, local, remote []*Forward, muxer *tubes.Muxer) {
	// We write all of the local forwards first to avoid unnecessarily blocking on the responses
	for _, fwd := range local {
		writeFlags(ch, true, false)
		ch.Write(toBytes(&fwd.listen))
		ch.Write(toBytes(&fwd.connect))
	}
	for _, fwd := range local {
		b := make([]byte, 1)
		io.ReadFull(ch, b)
		if b[0] == success {
			table.im.Lock()
			table.inbound[fwd.connect] = fwd.listen
			table.im.Unlock()
		}
	}
	for _, fwd := range remote {
		if listen(&fwd.connect, &fwd.listen, table, muxer) {
			writeFlags(ch, true, true)
			ch.Write(toBytes(&fwd.connect))
			ch.Write(toBytes(&fwd.listen))
			b := make([]byte, 1)
			io.ReadFull(ch, b)
			// TODO: handle cancelling
		}
	}
}

//ErrInvalidPortForwardingArgs returned when client receives unsupported -L or -R options
var ErrInvalidPortForwardingArgs = errors.New("port forwarding currently only supported with port:host:hostport format")

// ErrInvalidPFArgs is returned when there is a problem parsing portfowarding argument
var ErrInvalidPFArgs = errors.New("error parsing portforwarding argument")

//returns true if a forward slash exists
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

/*ParseForward takes in a PF argument and returns a newly populated *Forward
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
		err = ErrInvalidPFArgs
		return
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
			err = ErrInvalidPFArgs
			return
		}
		parts = append(parts, arg[1:end])
		if arg[end+1] != ':' { //must be followed by a colon to have a port number at a minimum
			logrus.Errorf("next char is not a colon: %v", arg)
			err = ErrInvalidPFArgs
			return
		}
		arg = arg[end+2:] //skip past trailing colon
	}
	if strings.Contains(arg, "[") {
		logrus.Info("second brackets found")
		start := strings.Index(arg, "[")
		end := strings.Index(arg, "]")
		if end <= start {
			err = ErrInvalidPFArgs
			return
		}
		if start > 0 {
			//check colon right before it
			if arg[start-1] != ':' { //must be preceded by a colon
				err = ErrInvalidPFArgs
				return
			}
			rawParts := strings.Split(arg[:start-1], ":")
			parts = append(parts, rawParts...)
		}
		parts = append(parts, arg[start+1:end])
		if arg[end+1] != ':' { //must be followed by a colon to have a port number at a minimum
			err = ErrInvalidPFArgs
			return
		}
		arg = arg[end+2:] //skip past trailing colon
	}
	//split and append whatever is left to parts
	rawParts := strings.Split(arg, ":")
	parts = append(parts, rawParts...)

	if len(parts) < 2 {
		err = ErrInvalidPFArgs
		return
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
		forward.connect.addr = parts[len(parts)-1]
		forward.connect.netType = pfUNIX
		parts = parts[:len(parts)-1]
	}
	switch len(parts) {
	case 0: //both listen and connect were sockets
		return
	case 1: // all that remains is listen_port (connect_socket already parsed)
		//listen_port:connect_socket				(1 no netType)
		forward.listen.addr = net.JoinHostPort(loopback, parts[0])

	case 2: // listen or connect was a socket. 2 args remain
		if forward.connect.netType == pfTCP {
			forward.connect.addr = net.JoinHostPort(parts[0], parts[1])
		} else if forward.listen.netType == pfTCP {
			forward.listen.addr = net.JoinHostPort(parts[0], parts[1])
		}
	case 3: //listen_port:connect_host:connect_port (3 no netType)
		forward.listen.addr = net.JoinHostPort(loopback, parts[0])
		forward.connect.addr = net.JoinHostPort(parts[1], parts[2])
	case 4: //listen_address:listen_port:connect_host:connect_port (4 no netType)
		forward.listen.addr = net.JoinHostPort(parts[0], parts[1])
		forward.connect.addr = net.JoinHostPort(parts[2], parts[3])
	default:
		err = ErrInvalidPFArgs
		return
	}

	return
}
