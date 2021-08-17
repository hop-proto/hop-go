package authgrants

import (
	"bytes"
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

//TODO(baumanl): Some of this may be over complex. Figure out best way to standardize/simplify.

//General Constants
const (
	MaxPortNumber  = 65535
	DefaultHopPort = 8888 //TODO(baumanl): default port? 8888 for now

	IntentRequest       = byte(1)
	IntentCommunication = byte(2)
	IntentConfirmation  = byte(3)
	IntentDenied        = byte(4)

	TypeLen = 1
)

//Intent Request and Communication constants
const (
	sha3Len     = 32
	usernameLen = 32
	sniLen      = 256
	portLen     = 2
	tubeTypeLen = 1
	reservedLen = 1
	irHeaderLen = sha3Len + 2*(usernameLen+sniLen) + portLen + tubeTypeLen + reservedLen

	sha3Offset  = 0
	cUserOffset = sha3Offset + sha3Len
	cSNIOffset  = cUserOffset + usernameLen
	sUserOffset = cSNIOffset + sniLen
	sSNIOffset  = sUserOffset + usernameLen
	portOffset  = sSNIOffset + sniLen
	tTypeOffset = portOffset + portLen
	lenOffset   = tTypeOffset + tubeTypeLen //Using the reserved byte to hold length of action (up to 256 bytes)
	actOffset   = lenOffset + reservedLen
)

//Intent Confirmation constants
const (
	deadlineOffset = 0
	deadlineLen    = 8
	intentConfSize = deadlineLen
)

//Intent Denied constants
const (
	//reasonLenOffset = 0 //1 byte to record length of reason
	reasonOffset = 1
)

type agMessage struct {
	msgType byte
	d       data
}

type data interface {
	toBytes() []byte
}

//intentRequestMsg contains all data fields of an intent request msg
type intentRequestMsg struct {
	sha3           [sha3Len]byte
	clientUsername string
	clientSNI      string
	serverUsername string
	serverSNI      string
	port           uint16
	tubeType       byte
	action         string
}

//intentCommunicationMsg contains all data fields of an intent comm msg
//Actually necessary to have different struct?
//TODO(baumanl): figure out best way to restructure to min. duplicate code
type intentCommunicationMsg struct {
	sha3           [sha3Len]byte
	clientUsername string
	clientSNI      string
	serverUsername string
	serverSNI      string
	port           uint16
	tubeType       byte
	action         []string
}

//intentConfirmationMsg contains deadline for an approved auth grant
type intentConfirmationMsg struct {
	Deadline int64 //Unix time
}

//intentDeniedMsg contains reason for a denied auth grant
type intentDeniedMsg struct {
	reason string
}

//Constructors
func newIntentRequest(digest [sha3Len]byte, sUser string, addr string, cmd string) *agMessage {
	user, _ := user.Current()
	cSNI, _ := os.Hostname()
	sSNI, p := parseAddr(addr)

	r := &intentRequestMsg{
		sha3:           digest,
		clientUsername: user.Username,
		clientSNI:      cSNI,
		serverUsername: sUser,
		serverSNI:      sSNI,
		port:           p,
		tubeType:       byte(1), //TODO(baumanl): how should this be used/enforced?
		action:         cmd,
	}
	return &agMessage{
		msgType: IntentRequest,
		d:       r,
	}
}

func newIntentConfirmation(t time.Time) *agMessage {
	c := &intentConfirmationMsg{
		Deadline: t.Unix(),
	}
	return &agMessage{
		msgType: IntentConfirmation,
		d:       c,
	}
}

func newIntentDenied(r string) *agMessage {
	c := &intentDeniedMsg{
		reason: r,
	}
	return &agMessage{
		msgType: IntentDenied,
		d:       c,
	}
}

//toBytes()
func (r *intentRequestMsg) toBytes() []byte {
	s := [irHeaderLen]byte{}
	copy(s[sha3Offset:cUserOffset], r.sha3[:])
	copy(s[cUserOffset:cSNIOffset], []byte(r.clientUsername))
	copy(s[cSNIOffset:sUserOffset], []byte(r.clientSNI))
	copy(s[sUserOffset:sSNIOffset], []byte(r.serverUsername))
	copy(s[sSNIOffset:portOffset], []byte(r.serverSNI))
	binary.BigEndian.PutUint16(s[portOffset:tTypeOffset], r.port)
	s[tTypeOffset] = r.tubeType
	s[lenOffset] = byte(len(r.action)) //TODO(baumanl): This only allows for actions up to 256 bytes (and no bounds checking atm)
	return append(s[:], []byte(r.action)...)
}

func (c *intentCommunicationMsg) toBytes() []byte { //TODO(baumanl): This is literally identical to the above function.
	s := [irHeaderLen]byte{}
	copy(s[sha3Offset:cUserOffset], c.sha3[:])
	copy(s[cUserOffset:cSNIOffset], []byte(c.clientUsername))
	copy(s[cSNIOffset:sUserOffset], []byte(c.clientSNI))
	copy(s[sUserOffset:sSNIOffset], []byte(c.serverUsername))
	copy(s[sSNIOffset:portOffset], []byte(c.serverSNI))
	binary.BigEndian.PutUint16(s[portOffset:tTypeOffset], c.port)
	s[tTypeOffset] = c.tubeType
	action := []byte(strings.Join(c.action, " "))
	s[lenOffset] = byte(len(action)) //TODO(baumanl): This only allows for actions up to 256 bytes (and no bounds checking atm)
	return append(s[:], action...)
}

func (c *intentConfirmationMsg) toBytes() []byte {
	s := [intentConfSize]byte{}
	binary.BigEndian.PutUint64(s[deadlineOffset:], uint64(c.Deadline))
	return s[:]
}

func (c *intentDeniedMsg) toBytes() []byte {
	s := []byte{byte(len(c.reason))}
	return append(s[:], []byte(c.reason)...)
}

func (a *agMessage) toBytes() []byte {
	return append([]byte{a.msgType}, a.d.toBytes()...)
}

//Given a byte slice return the string representation of the bytes before the first null byte.
func trimNullBytes(b []byte) string {
	i := bytes.Index(b, []byte{0})
	if i != -1 {
		return string(b[:i])
	}
	return string(b)
}

//fromBytes()
func fromIntentRequestBytes(b []byte) *intentRequestMsg {
	r := intentRequestMsg{}
	copy(r.sha3[:], b[sha3Offset:cUserOffset])
	r.clientUsername = trimNullBytes(b[cUserOffset:cSNIOffset])
	r.clientSNI = trimNullBytes(b[cSNIOffset:sUserOffset])
	r.serverUsername = trimNullBytes(b[sUserOffset:sSNIOffset])
	r.serverSNI = trimNullBytes(b[sSNIOffset:portOffset])
	r.port = binary.BigEndian.Uint16(b[portOffset:tTypeOffset])
	r.tubeType = b[tTypeOffset]
	r.action = string(b[actOffset:])
	return &r
}

func fromIntentCommunicationBytes(b []byte) *intentCommunicationMsg {
	r := intentCommunicationMsg{}
	copy(r.sha3[:], b[sha3Offset:cUserOffset])
	r.clientUsername = trimNullBytes(b[cSNIOffset:cSNIOffset])
	r.clientSNI = trimNullBytes(b[cSNIOffset:sUserOffset])
	r.serverUsername = trimNullBytes(b[sUserOffset:sSNIOffset])
	r.serverSNI = trimNullBytes(b[sSNIOffset:portOffset])
	r.port = binary.BigEndian.Uint16(b[portOffset:tTypeOffset])
	r.tubeType = b[lenOffset]
	r.action = strings.Split(string(b[actOffset:]), " ")
	return &r
}

func fromIntentConfirmationBytes(b []byte) *intentConfirmationMsg {
	n := intentConfirmationMsg{}
	n.Deadline = int64(binary.BigEndian.Uint64(b[deadlineOffset:]))
	return &n
}

func fromIntentDeniedBytes(b []byte) *intentDeniedMsg {
	d := intentDeniedMsg{}
	d.reason = string(b[reasonOffset:])
	return &d
}

//Other helper functions
func parseAddr(addr string) (string, uint16) { //addr of format host:port or host
	host := addr
	port := DefaultHopPort
	if strings.Contains(addr, ":") {
		i := strings.Index(addr, ":")
		port, _ = strconv.Atoi(addr[i+1:])
		host = addr[:i]
	}
	if port > MaxPortNumber {
		logrus.Fatal("port number out of range")
	}
	return host, uint16(port)
}

//ReadIntentRequest gets Intent Request bytes
func ReadIntentRequest(c net.Conn) ([]byte, error) {
	msgType := make([]byte, 1)
	c.Read(msgType)
	if msgType[0] == IntentRequest {
		irh := make([]byte, irHeaderLen)
		_, err := c.Read(irh)
		if err != nil {
			return nil, err
		}
		actionLen := int8(irh[irHeaderLen-1])
		action := make([]byte, actionLen)
		_, err = c.Read(action)
		if err != nil {
			return nil, err
		}
		return append(msgType, append(irh, action...)...), nil
	}
	return nil, errors.New("bad msg type")
}

//Gets Intent Communication bytes
func readIntentCommunication(c net.Conn) ([]byte, error) {
	msgType := make([]byte, 1)
	c.Read(msgType)
	if msgType[0] == IntentCommunication {
		irh := make([]byte, irHeaderLen)
		_, err := c.Read(irh)
		if err != nil {
			return nil, err
		}
		actionLen := int8(irh[irHeaderLen-1])
		action := make([]byte, actionLen)
		_, err = c.Read(action)
		if err != nil {
			return nil, err
		}
		return append(msgType, append(irh, action...)...), nil
	}
	return nil, errors.New("bad msg type")
}

//GetResponse Waits and reads IntentConfirmation or IntentDenied from net.Conn
func GetResponse(c net.Conn) ([]byte, byte, error) {
	responseType := make([]byte, 1)
	_, err := c.Read(responseType)
	if err != nil {
		return nil, responseType[0], err
	}
	logrus.Infof("Got response type: %v", responseType)
	//TODO(baumanl): SET TIMEOUT STUFF + BETTER ERROR CHECKING
	switch responseType[0] {
	case IntentConfirmation:
		conf := make([]byte, intentConfSize)
		_, err := c.Read(conf)
		if err != nil {
			return nil, responseType[0], err
		}
		return append(responseType, conf...), responseType[0], nil
	case IntentDenied:
		reasonLength := make([]byte, 1)
		_, err := c.Read(reasonLength)
		if err != nil {
			return nil, responseType[0], err
		}
		logrus.Infof("C: EXPECTING %v BYTES OF REASON", reasonLength)
		reason := make([]byte, int(reasonLength[0]))
		_, err = c.Read(reason)
		if err != nil {
			return nil, responseType[0], err
		}
		return append(append(responseType, reasonLength...), reason...), responseType[0], nil
	default:
		return nil, responseType[0], errors.New("bad msg type")
	}
}

//Makes an Intent Communication from an Intent Request (just change msg type)
func commFromReq(b []byte) []byte {
	return append([]byte{IntentCommunication}, b[TypeLen:]...)
}
