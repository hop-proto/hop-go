package main

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

//MSG Types
const (
	INTENT_REQUEST       = byte(0)
	INTENT_COMMUNICATION = byte(1)
	INTENT_CONFIRMATION  = byte(2)
	INTENT_DENIED        = byte(3)

	TYPE_LEN                         = 1
	SHA3_LEN                         = 32
	SNI_LEN                          = 256
	PORT_LEN                         = 2
	CHANNEL_TYPE_LEN                 = 1
	RESERVED_LEN                     = 1
	MIN_INTENT_REQUEST_HEADER_LENGTH = TYPE_LEN + SHA3_LEN + SNI_LEN + PORT_LEN + CHANNEL_TYPE_LEN + RESERVED_LEN
)

type IntentMsg interface {
	ToByteSlice() []byte
}

type IntentRequest struct {
	sha3ClientId   [SHA3_LEN]byte
	sni            [SNI_LEN]byte
	port           uint16
	channelType    byte
	associatedData []byte
}

type IntentCommunication struct {
	sha3ClientId   [SHA3_LEN]byte
	sni            [SNI_LEN]byte
	port           uint16
	channelType    byte
	associatedData []byte
}

func (m IntentRequest) ToByteSlice() []byte {
	slice := []byte{INTENT_REQUEST}
	// if m.Type == INTENT_REQUEST || m.Type == INTENT_COMMUNICATION {
	// 	slice := append(slice, m.)
	// } else if m.Type == INTENT_CONFIRMATION {

	// } else if m.Type == INTENT_DENIED {

	// }
}

//DEATH BY PARSING....AAAAAHHH
func BuildIntentRequest(sha3id [32]byte, action string, user string, addr string) []byte {

	/*These aren't currently part of the protocol
	but I feel like they are important?*/
	// client := os.Current().Username
	// clienthostname, err := os.Hostname()

	//Set the Msg type field
	request := []byte{INTENT_REQUEST}

	//Add the SHA3 Client Identifier
	request = append(request, sha3id[:]...)

	//TODO: Why is there a separate port field?
	//parse addr into host:port and port
	portstr := ""
	if strings.Contains(addr, ":") {
		i := strings.Index(addr, ":")
		portstr = addr[i+1:]
	}
	//TODO: make a correct sni? Should this also include desired user on remote server?
	// Figure out what what address to use (copied/modified from Davids gonet.go file)
	throwaway, err := net.Dial("udp", addr) //addr needs to be of form host:port
	if err != nil {
		logrus.Fatal("Failed to figure out address. Check addr is in <host>:<port> format.")
	}
	remoteAddr := throwaway.RemoteAddr()
	throwaway.Close()

	sniinfo := []byte(remoteAddr.String())
	if len(sniinfo) > 256 {
		logrus.Fatalf("Invalid SNI. Length exceeded 256 bytes")
	}
	sni := [256]byte{}
	for i, b := range sniinfo {
		sni[i] = b
	}
	//Add the SNI
	request = append(request, sni[:]...)

	//TODO: Is this necessary? Isn't this included in SNI? Can definitely be done cleaner if necessary
	//Add the PORT number
	if portstr != "" {
		MAXPORTNUMBER := 65535
		port, _ := strconv.Atoi(portstr)
		if port > MAXPORTNUMBER {
			logrus.Fatal("port number out of range")
		}
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(port))
		request = append(request, b...)
	} else {
		request = append(request, make([]byte, 2)...)
	}

	//Add the Channel Type (how is this determined...?/Why necessary...?)
	request = append(request, byte(0))

	//Reserved byte
	request = append(request, byte(0))

	//Associated data (action)
	request = append(request, []byte(action)...)

	return request

}

func ParseIntentRequest(intent []byte) {

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
