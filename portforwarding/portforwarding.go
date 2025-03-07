package portforwarding

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"hop.computer/hop/common"
	"hop.computer/hop/proxy"
	"hop.computer/hop/tubes"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	pfTCP    = 1
	pfUDP    = 2
	pfUNIX   = 3
	PfLocal  = 4
	PfRemote = 5
)

type NetType byte

type Forward struct {
	listen  net.Addr
	connect net.Addr
}

const (
	failure = 0
	success = 1
)

func readPacket(r io.Reader) (net.Addr, *byte, error) {
	b := make([]byte, 2)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, nil, err
	}

	netType := NetType(b[0])
	fwdType := b[1]

	var addrLen uint16
	err = binary.Read(r, binary.BigEndian, &addrLen)
	if err != nil {
		return nil, nil, err
	}

	addrBytes := make([]byte, addrLen)
	_, err = io.ReadFull(r, addrBytes)
	if err != nil {
		return nil, nil, err
	}

	addrStr := string(addrBytes)

	var addr net.Addr
	switch netType {
	case pfTCP:
		host, portStr, err := net.SplitHostPort(addrStr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid TCP address: %s", addrStr)
		}
		port, _ := strconv.Atoi(portStr)
		addr = &net.TCPAddr{IP: net.ParseIP(host), Port: port}

	case pfUDP:
		host, portStr, err := net.SplitHostPort(addrStr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid UDP address: %s", addrStr)
		}
		port, _ := strconv.Atoi(portStr)
		addr = &net.UDPAddr{IP: net.ParseIP(host), Port: port}

	case pfUNIX:
		addr = &net.UnixAddr{Name: addrStr, Net: "unix"}

	default:
		return nil, nil, fmt.Errorf("unknown network type: %d", netType)
	}

	return addr, &fwdType, nil
}

func toBytes(f net.Addr, fwdType int) []byte {
	var netType byte
	var addrStr string

	switch addr := f.(type) {
	case *net.TCPAddr:
		netType = byte(pfTCP)
		addrStr = net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))

	case *net.UDPAddr:
		netType = byte(pfUDP)
		addrStr = net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))

	case *net.UnixAddr:
		netType = byte(pfUNIX)
		addrStr = addr.Name

	default:
		logrus.Error("Unknown address type")
		return nil
	}

	addrLen := make([]byte, 2)
	binary.BigEndian.PutUint16(addrLen, uint16(len(addrStr)))

	var res []byte
	res = append(res, netType)
	res = append(res, byte(fwdType))
	res = append(res, addrLen...)
	res = append(res, []byte(addrStr)...)
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

// StartPFServer handles the PFControlTube and start the appropriate PF
// based on the client config
func StartPFServer(ch *tubes.Reliable, forward *Forward, muxer *tubes.Muxer) {

	local, fwdType, err := readPacket(ch)

	if err != nil {
		ch.Write([]byte{failure})
		ch.Close()
		return
	}

	if *fwdType == PfLocal {
		// This Dial is for creating a communication between the hop server(/client)
		// and the service that needs to be reached
		// TODO (paul) do we consider udp/unix here?
		throwawayConn, err := net.Dial(local.Network(), local.String())
		if err != nil {
			logrus.Error("PF: couldn't connect to local addr: ", err)
			ch.Write([]byte{failure})
			ch.Close()
			return
		}

		logrus.Debugf("PF: dialed address, %v", local.String())
		throwawayConn.Close()

		forward.connect = local

		ch.Write([]byte{success})

		return

	} else if *fwdType == PfRemote {

		// TODO (paul) this should be in the setupListenerAndForward function
		ch.Write([]byte{success})

		setupListenerAndForward(muxer, local)

	} else {
		logrus.Errorf("PF: closing porfforwarding session, bad fwdType %v", fwdType)
		ch.Write([]byte{failure})
		ch.Close()
		return
	}
}

// HandlePF create a connection with the requested service
// and proxy the connection to the PF tube. The PFTube and
// the established connections are closed in proxy.ProxyConnection
func HandlePF(ch tubes.Tube, forward *Forward, pfType int) {
	logrus.Debugf("add: connect %v listen %v", forward.connect, forward.listen)
	addr, valid := getAddress(forward, pfType)
	if !valid {
		logrus.Error("PF: Wrong forwarding type ", pfType)
		ch.Close()
		return
	}

	switch addr := addr.(type) {
	case *net.TCPAddr:
		conn, err := net.DialTCP(addr.Network(), nil, addr)
		if err != nil {
			logrus.Error("PF: couldn't connect to local TCP addr: ", err)
			ch.Close()
			return
		}
		wg := proxy.ReliableProxy(conn, ch)
		go func() {
			wg.Wait()
			logrus.Infof("PF: Closing TCP connection")
		}()

	case *net.UnixAddr:
		conn, err := net.DialUnix(addr.Network(), nil, addr)
		if err != nil {
			logrus.Error("PF: couldn't connect to local Unix socket: ", err)
			ch.Close()
			return
		}
		logrus.Infof("PF: Connected to Unix socket at %s", addr.Name)

		wg := proxy.ReliableProxy(conn, ch)
		go func() {
			wg.Wait()
			logrus.Infof("PF: Closing Unix socket connection")
		}()
	case *net.UDPAddr:
		if unreliableTube, ok := ch.(*tubes.Unreliable); ok {
			conn, err := net.DialUDP(addr.Network(), nil, addr)
			if err != nil {
				logrus.Error("PF: couldn't connect to local UDP addr: ", err)
				ch.Close()
				return
			}

			wg := proxy.UnreliableProxy(conn, unreliableTube)
			go func() {
				wg.Wait()
				logrus.Infof("PF: Closing UDP connection")
			}()
		} else {
			logrus.Error("PF: UDP connection are operated only over unreliable tubes")
			ch.Close()
		}

	default:
		logrus.Error("PF: Wrong address type")
		ch.Close()
	}
}

func getAddress(forward *Forward, pfType int) (net.Addr, bool) {
	switch pfType {
	case PfLocal:
		return forward.connect, true
	case PfRemote:
		return forward.listen, true
	default:
		return nil, false
	}
}

// PFClientLocal receive the server response from the PF control tube and start a new listener
// with the local address and for as many connection that he needs, it will create and forward to
// a new reliable PFtube. The listener is in TCP, then the tube is in reliable mode, otherwise, we
// have to implement a unreliable tube for tcp addresses

// InitiatePFClientRemote is initiated by the client on client session start.
// it writes the addr to dial for the remote server and send it through
// a control tube to ask the server to acknowledge.

func setupListenerAndForward(muxer *tubes.Muxer, addr net.Addr) {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		listener, err := net.ListenUDP(addr.Network(), addr)
		if err != nil {
			logrus.Errorf("PF: UDP listener can't start: %v", err)
			return
		}
		proxyTube, err := muxer.CreateUnreliableTube(common.PFTube)
		if err != nil {
			logrus.Errorf("PF: error creating proxy tube: %v", err)
			return
		}
		go proxy.UnreliableProxy(listener, proxyTube)

	case *net.TCPAddr:
		listener, err := net.ListenTCP(addr.Network(), addr)
		if err != nil {
			logrus.Errorf("PF: TCP listener can't start: %v", err)
			return
		}
		defer listener.Close()

		for {
			local, err := listener.Accept()
			if err != nil {
				logrus.Errorf("PF: TCP listener can't accept connection: %v", err)
				return
			}
			logrus.Infof("TCP Connection accepted from %s", local.RemoteAddr())

			proxyTube, err := muxer.CreateReliableTube(common.PFTube)
			if err != nil {
				logrus.Errorf("PF: error creating reliable proxy tube: %v", err)
				return
			}

			wg := proxy.ReliableProxy(local, proxyTube)
			go func() {
				wg.Wait()
				logrus.Infof("PF: Closing connection to %v", local.RemoteAddr())
			}()
		}

	case *net.UnixAddr:
		os.Remove(addr.Name)
		listener, err := net.ListenUnix(addr.Network(), addr)
		if err != nil {
			logrus.Errorf("PF: Unix listener can't start: %v", err)
			return
		}
		defer listener.Close()
		logrus.Infof("PF: Unix socket listening on %s", addr.Name)

		for {
			local, err := listener.Accept()
			if err != nil {
				logrus.Errorf("PF: Unix listener can't accept connection: %v", err)
				return
			}
			logrus.Infof("Unix Connection accepted from %s", local.RemoteAddr())

			proxyTube, err := muxer.CreateReliableTube(common.PFTube)
			if err != nil {
				logrus.Errorf("PF: error creating reliable proxy tube: %v", err)
				return
			}

			wg := proxy.ReliableProxy(local, proxyTube)
			go func() {
				wg.Wait()
				logrus.Infof("PF: Closing Unix socket connection")
			}()
		}

	default:
		logrus.Errorf("PF: Unsupported address type: %T", addr)
	}
}

func StartPFClient(forward *Forward, muxer *tubes.Muxer, pfType int) {
	pfControlTube, err := muxer.CreateReliableTube(common.PFControlTube)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer pfControlTube.Close()

	byteAddr := toBytes(forward.connect, pfType)
	_, err = pfControlTube.Write(byteAddr)
	if err != nil {
		logrus.Errorf("PF: Can't write in the PF control tube. %v", err)
		return
	}

	b := make([]byte, len(byteAddr))
	n, err := pfControlTube.Read(b)
	logrus.Debugf("PF: Client received message %x", b[:n])

	if err != nil || int(b[0]) != success {
		logrus.Errorf("PF: Server can't start remote port forwarding: %v", err)
		return
	}

	if pfType == PfLocal {
		setupListenerAndForward(muxer, forward.listen)

	} else if pfType == PfRemote {
		throwawayConn, err := net.Dial(forward.listen.Network(), forward.listen.String())
		if err != nil {
			logrus.Error("PF: couldn't connect to local addr: ", err)
			return
		}

		logrus.Debugf("PF: dialed address, %v", forward.listen.String())
		throwawayConn.Close()

	}
}

// ErrInvalidPortForwardingArgs returned when client receives unsupported -L or -R options
var ErrInvalidPortForwardingArgs = errors.New("port forwarding currently only supported with port:host:hostport format")

// ErrInvalidPFArgs is returned when there is a problem parsing portfowarding argument
var ErrInvalidPFArgs = errors.New("error parsing portforwarding argument")

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
func ParseForward(arg string, networkType int) (forward *Forward, err error) {
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
		parts = append(parts, arg[0:end+1])
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
		parts = append(parts, arg[start:end+1])
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

	createAddress := func(network int, ip string, port int) net.Addr {
		if network == pfUDP {
			return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
		}
		return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
	}

	if checkPath(parts[0]) {
		forward.listen = &net.UnixAddr{Name: parts[0], Net: "unix"}
		parts = parts[1:]
	}

	if checkPath(parts[len(parts)-1]) {
		forward.connect = &net.UnixAddr{Name: parts[len(parts)-1], Net: "unix"}
		parts = parts[:len(parts)-1]
	}

	switch len(parts) {
	case 0: // both listen and connect were sockets
		return forward, nil
	case 1: // all that remains is listen_port (connect_socket already parsed)
		//listen_port:connect_socket
		forward.listen = createAddress(networkType, loopback, parsePort(parts[0]))
	case 2:
		// listen or connect was a socket. 2 args remain
		if nil == forward.listen {
			forward.listen = createAddress(networkType, parts[0], parsePort(parts[1]))
		} else if nil == forward.connect {
			forward.connect = createAddress(networkType, parts[0], parsePort(parts[1]))
		}
	case 3:
		//listen_port:connect_host:connect_port
		forward.listen = createAddress(networkType, loopback, parsePort(parts[0]))
		forward.connect = createAddress(networkType, parts[1], parsePort(parts[2]))
	case 4:
		//listen_address:listen_port:connect_host:connect_port
		forward.listen = createAddress(networkType, parts[0], parsePort(parts[1]))
		forward.connect = createAddress(networkType, parts[2], parsePort(parts[3]))
	default:
		return nil, ErrInvalidPFArgs
	}

	return forward, err
}

func parsePort(portStr string) int {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}
