package authgrants

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

//General Constants
const (
	MAX_PORT_NUMBER  = 65535
	DEFAULT_HOP_PORT = 8888 //TODO: default port? 8888 for now

	INTENT_REQUEST       = byte(1)
	INTENT_COMMUNICATION = byte(2)
	INTENT_CONFIRMATION  = byte(3)
	INTENT_DENIED        = byte(4)

	TYPE_LEN = 1
)

//Intent Request and Communication constants
const (
	SHA3_LEN         = 32
	USERNAME_LEN     = 32
	SNI_LEN          = 256
	PORT_LEN         = 2
	CHANNEL_TYPE_LEN = 1
	RESERVED_LEN     = 1
	IR_HEADER_LENGTH = SHA3_LEN + 2*(USERNAME_LEN+SNI_LEN) + PORT_LEN + CHANNEL_TYPE_LEN + RESERVED_LEN

	SHA3_OFFSET   = 0
	CUSER_OFFSET  = SHA3_OFFSET + SHA3_LEN
	CSNI_OFFSET   = CUSER_OFFSET + USERNAME_LEN
	SUSER_OFFSET  = CSNI_OFFSET + SNI_LEN
	SSNI_OFFSET   = SUSER_OFFSET + USERNAME_LEN
	PORT_OFFSET   = SSNI_OFFSET + SNI_LEN
	CHTYPE_OFFSET = PORT_OFFSET + PORT_LEN
	LEN_OFFSET    = CHTYPE_OFFSET + CHANNEL_TYPE_LEN //Using the reserved byte to hold length of action (up to 256 bytes)
	ACT_OFFSET    = LEN_OFFSET + RESERVED_LEN
)

//Intent Confirmation constants
const (
	DEADLINE_OFFSET  = 0
	DEADLINE_LEN     = 8
	INTENT_CONF_SIZE = DEADLINE_LEN
)

//Intent Denied constants
const (
	REASON_LEN_OFFSET = 0 //1 byte to record length of reason
	REASON_OFFSET     = 1
)

type AgcMessage struct {
	msgType byte
	d       Data
}

type Data interface {
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

//Actually necessary to have different struct?
//TODO: figure out best way to restructure to min. duplicate code
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
	Deadline int64 //Unix time
}

type IntentDenied struct {
	reason string
}

//Constructors
func NewIntentRequest(digest [SHA3_LEN]byte, sUser string, addr string, cmd []string) *AgcMessage {
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
	return &AgcMessage{
		msgType: INTENT_REQUEST,
		d:       r,
	}
}

func NewIntentCommunication(r *IntentRequest) *AgcMessage {
	c := &IntentCommunication{
		sha3:           r.sha3,
		clientUsername: r.clientUsername,
		clientSNI:      r.clientSNI,
		serverUsername: r.serverUsername,
		serverSNI:      r.serverSNI,
		port:           r.port,
		channelType:    r.channelType,
		action:         r.action,
	}
	return &AgcMessage{
		msgType: INTENT_COMMUNICATION,
		d:       c,
	}
}

func NewIntentConfirmation(t time.Time) *AgcMessage {
	c := &IntentConfirmation{
		Deadline: t.Unix(),
	}
	return &AgcMessage{
		msgType: INTENT_CONFIRMATION,
		d:       c,
	}
}

func NewIntentDenied(r string) *AgcMessage {
	c := &IntentDenied{
		reason: r,
	}
	return &AgcMessage{
		msgType: INTENT_DENIED,
		d:       c,
	}
}

//toBytes()
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

func (c *IntentCommunication) toBytes() []byte { //TODO: This is literally identical to the above function.
	s := [IR_HEADER_LENGTH]byte{}
	copy(s[SHA3_OFFSET:CUSER_OFFSET], c.sha3[:])
	copy(s[CUSER_OFFSET:CSNI_OFFSET], []byte(c.clientUsername))
	copy(s[CSNI_OFFSET:SUSER_OFFSET], []byte(c.clientSNI))
	copy(s[SUSER_OFFSET:SSNI_OFFSET], []byte(c.serverUsername))
	copy(s[SSNI_OFFSET:PORT_OFFSET], []byte(c.serverSNI))
	binary.BigEndian.PutUint16(s[PORT_OFFSET:CHTYPE_OFFSET], c.port)
	s[CHTYPE_OFFSET] = c.channelType
	action := []byte(strings.Join(c.action, " "))
	s[LEN_OFFSET] = byte(len(action)) //TODO: This only allows for actions up to 256 bytes (and no bounds checking atm)
	return append(s[:], action...)
}

func (c *IntentConfirmation) toBytes() []byte {
	s := [INTENT_CONF_SIZE]byte{}
	binary.BigEndian.PutUint64(s[DEADLINE_OFFSET:], uint64(c.Deadline))
	return s[:]
}

func (c *IntentDenied) toBytes() []byte {
	s := []byte{byte(len(c.reason))}
	return append(s[:], []byte(c.reason)...)
}

func (a *AgcMessage) ToBytes() []byte {
	return append([]byte{a.msgType}, a.d.toBytes()...)
}

//fromBytes()
func FromIntentRequestBytes(b []byte) *IntentRequest {
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

func FromIntentCommunicationBytes(b []byte) *IntentCommunication {
	r := IntentCommunication{}
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

func FromIntentConfirmationBytes(b []byte) *IntentConfirmation {
	n := IntentConfirmation{}
	n.Deadline = int64(binary.BigEndian.Uint64(b[DEADLINE_OFFSET:]))
	return &n
}

func FromIntentDeniedBytes(b []byte) *IntentDenied {
	d := IntentDenied{}
	d.reason = string(b[REASON_OFFSET:])
	return &d
}

//Other helper functions
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

func ReadIntentRequest(c net.Conn) ([]byte, error) {
	msgType := make([]byte, 1)
	c.Read(msgType)
	if msgType[0] == INTENT_REQUEST {
		irh := make([]byte, IR_HEADER_LENGTH)
		_, err := c.Read(irh)
		if err != nil {
			return nil, err
		}
		actionLen := int8(irh[IR_HEADER_LENGTH-1])
		action := make([]byte, actionLen)
		_, err = c.Read(action)
		if err != nil {
			return nil, err
		}
		return append(msgType, append(irh, action...)...), nil
	}
	return nil, errors.New("bad msg type")
}

func ReadIntentCommunication(c net.Conn) ([]byte, error) {
	msgType := make([]byte, 1)
	c.Read(msgType)
	if msgType[0] == INTENT_COMMUNICATION {
		irh := make([]byte, IR_HEADER_LENGTH)
		_, err := c.Read(irh)
		if err != nil {
			return nil, err
		}
		actionLen := int8(irh[IR_HEADER_LENGTH-1])
		action := make([]byte, actionLen)
		_, err = c.Read(action)
		if err != nil {
			return nil, err
		}
		return append(msgType, append(irh, action...)...), nil
	}
	return nil, errors.New("bad msg type")
}

func GetResponse(c net.Conn) ([]byte, error) {
	responseType := make([]byte, 1)
	_, err := c.Read(responseType)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("Got response type: %v", responseType)
	//TODO: SET TIMEOUT STUFF + BETTER ERROR CHECKING
	if responseType[0] == INTENT_CONFIRMATION {
		conf := make([]byte, INTENT_CONF_SIZE)
		_, err := c.Read(conf)
		if err != nil {
			return nil, err
		}
		return append(responseType, conf...), nil
	} else if responseType[0] == INTENT_DENIED {
		reason_length := make([]byte, 1)
		_, err := c.Read(reason_length)
		if err != nil {
			return nil, err
		}
		logrus.Infof("C: EXPECTING %v BYTES OF REASON", reason_length)
		reason := make([]byte, int(reason_length[0]))
		_, err = c.Read(reason)
		if err != nil {
			return nil, err
		}
		return append(append(responseType, reason_length...), reason...), nil
	}
	return nil, errors.New("bad msg type")
}

//Makes an Intent Communication from an Intent Request (change msg type)
func CommFromReq(b []byte) []byte {
	return append([]byte{INTENT_COMMUNICATION}, b[TYPE_LEN:]...)
}
