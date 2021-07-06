package authgrants

import (
	"encoding/binary"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

//MSG Types
const (
	MAX_PORT_NUMBER  = 65535
	DEFAULT_HOP_PORT = 8888 //TODO: default port? 8888 for now

	INTENT_REQUEST       = byte(1)
	INTENT_COMMUNICATION = byte(2)
	INTENT_CONFIRMATION  = byte(3)
	INTENT_DENIED        = byte(4)

	TYPE_LEN = 1

	SHA3_LEN         = 32
	USERNAME_LEN     = 32
	SNI_LEN          = 256
	PORT_LEN         = 2
	CHANNEL_TYPE_LEN = 1
	RESERVED_LEN     = 1
	IR_HEADER_LENGTH = TYPE_LEN + SHA3_LEN + 2*(USERNAME_LEN+SNI_LEN) + PORT_LEN + CHANNEL_TYPE_LEN + RESERVED_LEN

	SHA3_OFFSET   = 0
	CUSER_OFFSET  = SHA3_LEN
	CSNI_OFFSET   = CUSER_OFFSET + USERNAME_LEN
	SUSER_OFFSET  = CSNI_OFFSET + SNI_LEN
	SSNI_OFFSET   = SUSER_OFFSET + USERNAME_LEN
	PORT_OFFSET   = SSNI_OFFSET + SNI_LEN
	CHTYPE_OFFSET = PORT_OFFSET + PORT_LEN
	LEN_OFFSET    = CHTYPE_OFFSET + CHANNEL_TYPE_LEN //Using the reserved byte to hold length of action (up to 256 bytes)
	ACT_OFFSET    = LEN_OFFSET + RESERVED_LEN
)

type IntentMsg interface {
	toBytes() []byte
}

type IntentRequest struct {
	sha3           [SHA3_LEN]byte
	clientUsername string
	clientSNI      string
	serverUsername string
	serverSNI      string
	port           uint16
	channelType    byte
	action         []string
}

type IntentCommunication struct {
	sha3           [SHA3_LEN]byte
	clientUsername string
	clientSNI      string
	serverUsername string
	serverSNI      string
	port           uint16
	channelType    byte
	action         []string
}

type IntentConfirmation struct {
	//timeline
}

type IntentDenial struct {
	//reason
}

func NewIntentRequest(digest [SHA3_LEN]byte, sUser string, addr string, cmd []string) *IntentRequest {
	user, _ := user.Current()
	cSNI, _ := os.Hostname()
	sSNI, p := parseAddr(addr)
	r := &IntentRequest{
		sha3:           digest,
		clientUsername: user.Username,
		clientSNI:      cSNI,
		serverUsername: sUser,
		serverSNI:      sSNI,
		port:           p,
		channelType:    byte(1), //TODO
		action:         cmd,
	}
	return r
}

func (r *IntentRequest) toBytes() []byte {
	s := [IR_HEADER_LENGTH]byte{}
	copy(s[SHA3_OFFSET:CUSER_OFFSET], r.sha3[:])
	copy(s[CUSER_OFFSET:CSNI_OFFSET], []byte(r.clientUsername))
	copy(s[CSNI_OFFSET:SUSER_OFFSET], []byte(r.clientSNI))
	copy(s[SUSER_OFFSET:SSNI_OFFSET], []byte(r.serverUsername))
	copy(s[SSNI_OFFSET:PORT_OFFSET], []byte(r.serverSNI))
	binary.BigEndian.PutUint16(s[PORT_OFFSET:CHTYPE_OFFSET], r.port)
	s[CHTYPE_OFFSET] = r.channelType
	action := []byte(strings.Join(r.action, " "))
	s[LEN_OFFSET] = byte(len(action)) //TODO: This only allows for actions up to 256 bytes (and no bounds checking atm)
	return append(s[:], action...)
}

func fromBytes(b []byte) *IntentRequest {
	r := IntentRequest{}
	copy(r.sha3[:], b[SHA3_OFFSET:CUSER_OFFSET])
	r.clientUsername = string(b[CUSER_OFFSET:CSNI_OFFSET])
	r.clientSNI = string(b[CSNI_OFFSET:SUSER_OFFSET])
	r.serverUsername = string(b[SUSER_OFFSET:SSNI_OFFSET])
	r.serverSNI = string(b[SSNI_OFFSET:PORT_OFFSET])
	r.port = binary.BigEndian.Uint16(b[PORT_OFFSET:CHTYPE_OFFSET])
	r.channelType = b[CHTYPE_OFFSET]
	r.action = strings.Split(string(b[ACT_OFFSET:]), " ")
	return &r
}

func GetAuthGrant(digest [SHA3_LEN]byte, sUser string, addr string, cmd []string) bool {
	intent := NewIntentRequest(digest, sUser, addr, cmd)
	c, err := net.Dial("unix", "echo1.sock") //TODO: address of UDS
	if err != nil {
		logrus.Fatal(err)
	}
	defer c.Close()
	logrus.Infof("C2: CONNECTED TO UDS: [%v]", c.RemoteAddr().String())
	c.Write(intent.toBytes())

	buf := make([]byte, 19)
	n, err := c.Read(buf)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("C2: Client got: %v", string(buf[0:n]))
	return string(buf[0:n]) == "INTENT_CONFIRMATION"
}

func parseAddr(addr string) (string, uint16) { //addr of format host:port or host
	host := addr
	port := DEFAULT_HOP_PORT
	if strings.Contains(addr, ":") {
		i := strings.Index(addr, ":")
		port, _ = strconv.Atoi(addr[i+1:])
		host = addr[:i]
	}
	if port > MAX_PORT_NUMBER {
		logrus.Fatal("port number out of range")
	}
	return host, uint16(port)
}

func (m IntentRequest) String() string {
	panic("Not implemented")
}

/*How the principal should respond to different authorization
grant message types*/
func principalHandleMsg(msg []byte) {
	msgType := msg[0]
	switch msgType {
	case INTENT_REQUEST:
		//clientID := msg[1:33] //first 32 bytes of data
		// SNI := //next 256 bytes;
		// aport := //next 2 bytes
		// channelType := //next byte
		// reserved := //next byte
		// assocData := //remaining bytes (desired command to run)
		//Prompt user with request
		//send INTENT_DENIED to client if user denies
		//otherwise initiate network proxy channel w/ client
		//initiate hop session with server through proxy channel w/ client
		//send INTENT_COMMUNICATION msg to server

	case INTENT_CONFIRMATION:
		//if this msg came from the server that we previously sent an INTENT_COMMUNICATION to...
		//data := timestamp deadline set by the server for the client to complete the Hop handshake
		//forward this message to the client
		//otherwise error

	case INTENT_DENIED:
		//if this msg came from the server that we previously sent an INTENT_COMMUNICATION to...
		//data := //reason for denial
		//forward this message to the client
		//otherwise error

	default:
		//error
	}
}

/*How the server should respond to different Auth Grant msg types */
func serverHandleMsg(msg []byte) {
	msgType := msg[0]
	switch msgType {
	case INTENT_COMMUNICATION:
		// clientID := msg[1:33]//first 32 bytes of data
		// SNI := //next 256 bytes
		// port := //next 2 bytes
		// channelType := //next byte
		// reserved := //next byte
		// assocData := //remaining bytes (desired command to run)
		// //Check server policies
		// //send INTENT_CONFIRMATION or INTENT_DENIED

	default:
		//error
	}
}

/*how the client should respond*/
func clientHandleMsg(msg []byte) {
	msgType := msg[0]
	switch msgType {
	case INTENT_CONFIRMATION:
		//data := //timestamp deadline set by the server for the client to complete the Hop handshake
	case INTENT_DENIED:
		//data := //reason for denial

	default:
		//error
	}
}
