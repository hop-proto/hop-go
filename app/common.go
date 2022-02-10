package app

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/certs"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
)

//Defaults and constants for starting a hop session
const (
	DefaultHopPort        = "7777"
	DefaultKeyPath        = "/.hop/key"
	clientUsage           = "hop [user@]host[:port] [-K or -k path] [-L port:host:hostport] [-R port:host:hostport] [-N] [-c cmd] [-q] [-h]"
	TestDataPathPrefixDef = "../../certs/"
	DefaultHopAuthSocket  = "@hopauth"
)

//Tube Type constants
const (
	ExecTube      = byte(1)
	AuthGrantTube = byte(2)
	NetProxyTube  = byte(3) // Net Proxy should maybe be unreliable tube?
	UserAuthTube  = byte(4)
	LocalPFTube   = byte(5)
	RemotePFTube  = byte(6)
)

var hostToIPAddr = map[string]string{ //TODO(baumanl): this should be dealt with in some user hop config file
	"scratch-01": "10.216.2.64",
	"scratch-02": "10.216.2.128",
	"scratch-07": "10.216.2.208",
	"localhost":  "127.0.0.1",
}

//ErrInvalidPortForwardingArgs returned when client receives unsupported -L or -R options
var ErrInvalidPortForwardingArgs = errors.New("port forwarding currently only supported with port:host:hostport format")

//ErrClientInvalidUsage returned by client when unable to parse command line arguments
var ErrClientInvalidUsage = errors.New("usage: " + clientUsage)

//ErrClientLoadingKeys returned by client (principal) when unable to load keys from specified location
var ErrClientLoadingKeys = errors.New("unable to load keys")

//ErrClientGettingAuthorization  is returned by client when it can't get
var ErrClientGettingAuthorization = errors.New("failed to get authorization")

//ErrClientStartingUnderlying is returned by client when it can't start transport layer conn
var ErrClientStartingUnderlying = errors.New("error starting underlying conn")

//ErrClientUnauthorized is returned by client when it is not authorized to perform the action it requested
var ErrClientUnauthorized = errors.New("client not authorized")

//ErrClientStartingExecTube is returned by client when cmd execution and/or I/O redirection fails
var ErrClientStartingExecTube = errors.New("failed to start session")

//ErrInvalidPFArgs is returned when there is a problem parsing portfowarding argument
var ErrInvalidPFArgs = errors.New("error parsing portforwarding argument")

//NewTestServerConfig populates server config and verify config with sample cert data
func NewTestServerConfig(testDataPathPrefix string) (*transport.ServerConfig, *transport.VerifyConfig) {
	keyPair, err := keys.ReadDHKeyFromPEMFile(testDataPathPrefix + "testdata/leaf-key.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH KEYPAIR %v", err)
	}
	certificate, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/leaf.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH CERTS %v", err)
	}
	intermediate, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/intermediate.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH INT CERTS %v", err)
	}
	root, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/root.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH ROOT CERT %v", err)
	}
	err = certs.VerifyParent(certificate, intermediate)
	if err != nil {
		logrus.Fatal("Verify Parent Issue: ", err)
	}
	err = certs.VerifyParent(intermediate, root)
	if err != nil {
		logrus.Fatal("Verify Parent Issue: ", err)
	}
	err = certs.VerifyParent(root, root)
	if err != nil {
		logrus.Fatal("Verify Parent Issue: ", err)
	}

	server := transport.ServerConfig{
		KeyPair:      keyPair,
		Certificate:  certificate,
		Intermediate: intermediate,
	}
	verify := transport.VerifyConfig{
		Store: certs.Store{},
	}
	verify.Store.AddCertificate(root)
	return &server, &verify
}

//KeyGen generates a new key pair and adds it to local authorized keys file
func KeyGen(dir string, filename string, addToAuthKeys bool) (*keys.X25519KeyPair, error) {
	suffix := dir + "/" + filename
	pair := keys.GenerateNewX25519KeyPair()
	path, _ := os.UserHomeDir()
	path += dir
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.Mkdir(path, fs.ModeDir|0700)
		if err != nil {
			logrus.Error(err)
			return nil, err
		}
	}
	path += "/" + filename
	f, e := os.Create(path)
	if e != nil {
		logrus.Errorf("error opening default key file: %v", e)
		return nil, e
	}
	logrus.Infof("adding private to ~%v: %v", suffix, pair.Private.String())
	f.WriteString(pair.Private.String())
	f.Close()

	path, _ = os.UserHomeDir()
	path += suffix + ".pub"
	f, e = os.Create(path)
	if e != nil {
		logrus.Errorf("error opening default key file: %v", e)
		return nil, e
	}
	logrus.Infof("adding public to ~%v.pub: %v", suffix, pair.Public.String())
	f.WriteString(pair.Public.String())
	f.Close()
	if addToAuthKeys {
		logrus.Info("adding to authorized keys")
		path, _ = os.UserHomeDir()
		path += dir
		path += "/authorized_keys" //adds the key to its own authorized key file so that localhost operations will work
		_, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			logrus.Info("file does not exist, creating...")
			f, e := os.Create(path)
			if e != nil {
				logrus.Error(e)
				return nil, e
			}
			f.Close()
		}
		auth, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
		if e != nil {
			logrus.Errorf("error opening auth key file: %v", e)
			return nil, e
		}
		defer auth.Close()
		logrus.Infof("adding public to auth keys: %v", pair.Public.String())
		auth.WriteString(pair.Public.String())
		auth.WriteString("\n")
	}
	return pair, nil
}

//Fwd holds state related to portforwarding parsed from cmdline or config
type Fwd struct {
	Listensock        bool   // true if listening on a socket (not a host, port pair)
	Connectsock       bool   // true if destination is a socket
	Listenhost        string // optional bind address on listening peer
	Listenportorpath  string // port to listen on or socket to listen on
	Connecthost       string // optional final destination (not used if final dest is a socket)
	Connectportorpath string // final dest port or socket path
}

/*-R port (ssh acts as a SOCKS 4/5 proxy) HOP NOT SUPPORTED -R
A. (3) -R port:host:hostport or 				-L port:host:hostport 				--> listen_port:connect_host:connect_port (3 no sock)
B. (2) -R port:local_socket or 					-L port:remote_socket 				--> listen_port:connect_socket				(1 no sock)

C. (4) -R bind_address:port:host:hostport or 	-L bind_address:port:host:hostport 	--> listen_address:listen_port:connect_host:connect_port (4 no sock)
D. (3) -R bind_address:port:local_socket or 	-L bind_address:port:remote_socket 	--> listen_address:listen_port:connect_socket (2 no sock)

E. (3) -R remote_socket:host:hostport or 		-L local_socket:host:hostport 		--> listen_socket:connect_host:connect_port (2 no sock)
F. (2) -R remote_socket:local_socket or 		-L local_socket:remote_socket 		--> listen_socket:connect_socket (0 no sock)

*/

//returns true if a forward slash exists
func checkPath(arg string) bool {
	return strings.Contains(arg, "/")
}

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

/*ParseForward takes in a PF argument and populates fwdStruct with data
if Remote: listen is on the remote peer (hop server) and connect is contacted by the local peer
if Local: listen is on the local peer (hop client) and connect is contacted by the remote peer
[listenhost:]listenport|listenpath:connecthost:connectport|connectpath
 *	listenpath:connectpath
*/
func ParseForward(arg string, fwdStruct *Fwd) error {
	//TODO: expand env vars
	//skip leading/trailing whitespace
	arg = strings.TrimSpace(arg)
	parts := []string{}

	nleft := strings.Count(arg, "[")
	nright := strings.Count(arg, "]")
	if nleft > 2 || nleft != nright {
		return ErrInvalidPFArgs
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
			return ErrInvalidPFArgs
		}
		parts = append(parts, arg[1:end])
		if arg[end+1] != ':' { //must be followed by a colon to have a port number at a minimum
			logrus.Errorf("next char is not a colon: %v", arg)
			return ErrInvalidPFArgs
		}
		arg = arg[end+2:] //skip past trailing colon
	}
	if strings.Contains(arg, "[") {
		logrus.Info("second brackets found")
		start := strings.Index(arg, "[")
		end := strings.Index(arg, "]")
		if end <= start {
			return ErrInvalidPFArgs
		}
		if start > 0 {
			//check colon right before it
			if arg[start-1] != ':' { //must be preceded by a colon
				return ErrInvalidPFArgs
			}
			rawParts := strings.Split(arg[:start-1], ":")
			parts = append(parts, rawParts...)
		}
		parts = append(parts, arg[start+1:end])
		if arg[end+1] != ':' { //must be followed by a colon to have a port number at a minimum
			return ErrInvalidPFArgs
		}
		arg = arg[end+2:] //skip past trailing colon
	}
	//split and append whatever is left to parts
	rawParts := strings.Split(arg, ":")
	parts = append(parts, rawParts...)

	if len(parts) < 2 {
		return ErrInvalidPFArgs
	}

	fwdStruct.Listensock = false
	fwdStruct.Connectsock = false

	if checkPath(parts[0]) {
		fwdStruct.Listenportorpath = parts[0]
		fwdStruct.Listensock = true
		parts = parts[1:]
	}
	if checkPath(parts[len(parts)-1]) {
		fwdStruct.Connectportorpath = parts[len(parts)-1]
		fwdStruct.Connectsock = true
		parts = parts[:len(parts)-1]
	}
	switch len(parts) {
	case 0: //both listen and connect were sockets
		return nil
	case 1: // all that remains is listen_port (connect_socket already parsed)
		//listen_port:connect_socket				(1 no sock)
		fwdStruct.Listenportorpath = parts[0]

	case 2: // listen or connect was a socket. 2 args remain
		if !fwdStruct.Connectsock {
			fwdStruct.Connecthost = parts[0]
			fwdStruct.Connectportorpath = parts[1]
		} else if !fwdStruct.Listensock {
			fwdStruct.Listenhost = parts[0]
			fwdStruct.Listenportorpath = parts[1]
		}
	case 3: //listen_port:connect_host:connect_port (3 no sock)
		fwdStruct.Listenportorpath = parts[0]
		fwdStruct.Connecthost = parts[1]
		fwdStruct.Connectportorpath = parts[2]
	case 4: //listen_address:listen_port:connect_host:connect_port (4 no sock)
		fwdStruct.Listenhost = parts[0]
		fwdStruct.Listenportorpath = parts[1]
		fwdStruct.Connecthost = parts[2]
		fwdStruct.Connectportorpath = parts[3]
	default:
		return ErrInvalidPFArgs
	}

	return nil
}
