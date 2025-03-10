package portforwarding

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"hop.computer/hop/common"
	"hop.computer/hop/proxy"
	"hop.computer/hop/tubes"

	"github.com/sirupsen/logrus"
)

const (
	PfTCP    = 1
	PfUDP    = 2
	PfUNIX   = 3
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

// readPacket parse the addresses sent from the client and convert them to net.Addr objects
func readPacket(r io.Reader) (net.Addr, byte, error) {
	b := make([]byte, 2)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, 0, err
	}

	netType := NetType(b[0])
	fwdType := b[1]

	var addrLen uint16
	err = binary.Read(r, binary.BigEndian, &addrLen)
	if err != nil {
		return nil, 0, err
	}

	addrBytes := make([]byte, addrLen)
	_, err = io.ReadFull(r, addrBytes)
	if err != nil {
		return nil, 0, err
	}

	addrStr := string(addrBytes)

	var addr net.Addr
	switch netType {
	case PfTCP:
		host, portStr, err := net.SplitHostPort(addrStr)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid TCP address: %s", addrStr)
		}
		port, _ := strconv.Atoi(portStr)
		addr = &net.TCPAddr{IP: net.ParseIP(host), Port: port}

	case PfUDP:
		host, portStr, err := net.SplitHostPort(addrStr)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid UDP address: %s", addrStr)
		}
		port, _ := strconv.Atoi(portStr)
		addr = &net.UDPAddr{IP: net.ParseIP(host), Port: port}

	case PfUNIX:
		addr = &net.UnixAddr{Name: addrStr, Net: "unix"}

	default:
		return nil, 0, fmt.Errorf("unknown network type: %d", netType)
	}

	return addr, fwdType, nil
}

// toBytes writes the PF information to send them to the server
func toBytes(f net.Addr, fwdType int) []byte {
	var netType byte
	var addrStr string

	switch addr := f.(type) {
	case *net.TCPAddr:
		netType = byte(PfTCP)
		addrStr = net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))

	case *net.UDPAddr:
		netType = byte(PfUDP)
		addrStr = net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))

	case *net.UnixAddr:
		netType = byte(PfUNIX)
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

// StartPFServer handles the PFControlTube and starts the appropriate PF
// based on the client's PF information sent through the common.PFControlTube.
func StartPFServer(ch *tubes.Reliable, forward *Forward, muxer *tubes.Muxer) {

	addr, fwdType, err := readPacket(ch)

	if err != nil {
		ch.Write([]byte{failure})
		ch.Close()
		return
	}

	if fwdType == PfLocal {
		// This Dial is for creating a communication between the hop server(/client)
		// and the service that needs to be reached
		throwawayConn, err := net.Dial(addr.Network(), addr.String())
		if err != nil {
			logrus.Error("PF: couldn't connect to local addr: ", err)
			ch.Write([]byte{failure})
			ch.Close()
			return
		}

		logrus.Debugf("PF: dialed address, %v", addr.String())
		throwawayConn.Close()

		forward.connect = addr

		ch.Write([]byte{success})

		return

	} else if fwdType == PfRemote {

		ch.Write([]byte{success})

		setupListenerAndForward(muxer, addr)

	} else {
		logrus.Errorf("PF: closing porfforwarding session, bad fwdType %v", fwdType)
		ch.Write([]byte{failure})
		ch.Close()
		return
	}
}

// HandlePF establishes a connection with the requested service
// and proxies the data through the provided PF tube.
//
// - For TCP and Unix socket connections, it creates a reliable proxy.
// - For UDP connections, it ensures the use of an unreliable tube.
//
// The PFTube and established connections are automatically closed
// within proxy.ReliableProxy or proxy.UnreliableProxy
func HandlePF(ch tubes.Tube, forward *Forward) {
	addr := forward.connect

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

// setupListenerAndForward sets up a listener on the specified address and forwards
// incoming connections through a proxy tube.
//
//   - UDP: Creates a UDP listener and forwards packets through an unreliable proxy tube.
//   - TCP: Creates a TCP listener, accepts incoming connections, and forwards them
//     through a reliable proxy tube
//   - Unix Sockets: Listen the configured Unix socket and forwards connections
//     through a reliable proxy tube.
//
// This method is called by the client if PF is Local and the server if PF is remote
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

// StartPFClient is called by the client when local or remote port forwarding
// is specified in the client configuration. It establishes the control tube
// used to share address information with the server.
func StartPFClient(forward *Forward, muxer *tubes.Muxer, pfType int) {
	pfControlTube, err := muxer.CreateReliableTube(common.PFControlTube)
	if err != nil {
		logrus.Error(err)
		return
	}
	defer pfControlTube.Close()

	addr := forward.connect

	if pfType == PfRemote {
		addr = forward.listen
	}

	byteAddr := toBytes(addr, pfType)
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

// ErrInvalidPFArgs is returned when there is a problem parsing argument
var ErrInvalidPFArgs = errors.New("PF: Error parsing argument")

// returns true if a forward slash exists
func checkPath(arg string) bool {
	return strings.Contains(arg, "/")
}

// ParseForward takes in a PF argument and populates Forward with data
// if Remote: listen is on the remote peer (hop server) and connect is contacted by the local peer
// if Local: listen is on the local peer (hop client) and connect is contacted by the remote peer
// [listen_host:]listen_port|listen_path:connect_host:connect_port|connect_path
// listen_path:connect_path
func ParseForward(arg string, networkType int) (forward *Forward, err error) {
	loopback := "127.0.0.1"
	//TODO: expand env vars
	//skip leading/trailing whitespace
	arg = strings.TrimSpace(arg)
	var parts []string

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
		if network == PfUDP {
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
