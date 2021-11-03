package authgrants

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"time"
)

//TODO(baumanl): Some of this may be overly complex. Figure out best way to standardize/simplify.

//General Constants
const (
	IntentRequest       = byte(1)
	IntentCommunication = byte(2)
	IntentConfirmation  = byte(3)
	IntentDenied        = byte(4)
)

//ErrUnknownMessage used when msgtype does not match any of the authorization grant protocol defined messages.
var ErrUnknownMessage = errors.New("received message with unknown message type")

//ErrIntentDenied indicates an intent request was denied
var ErrIntentDenied = errors.New("received intent denied message")

//Action Type Constants
const (
	ShellAction    = byte(1)
	CommandAction  = byte(2)
	LocalPFAction  = byte(3)
	RemotePFAction = byte(4)
)

//Intent Request and Communication constants
const (
	sha3Len              = 32
	usernameLen          = 32
	sniLen               = 256
	portLen              = 2
	actionTypeLen        = 1
	reservedLen          = 1
	associatedDataLenLen = 2
	irHeaderLen          = sha3Len + 2*(usernameLen+sniLen) + portLen + actionTypeLen + reservedLen + associatedDataLenLen

	sha3Offset              = 0
	cUserOffset             = sha3Offset + sha3Len
	cSNIOffset              = cUserOffset + usernameLen
	sUserOffset             = cSNIOffset + sniLen
	sSNIOffset              = sUserOffset + usernameLen
	portOffset              = sSNIOffset + sniLen
	actionTypeOffset        = portOffset + portLen
	associatedDataLenOffset = actionTypeOffset + actionTypeLen + reservedLen
	associatedDataOffset    = actionTypeOffset + actionTypeLen + reservedLen + associatedDataLenLen //2 bytes for length of associated data
)

//Intent Confirmation constants
const (
	deadlineOffset = 0
	deadlineLen    = 8
)

//Intent Denied constants
const (
	reasonOffset = 1
)

type agMessage struct {
	msgType byte
	d       data
}

const (
	dataOffset = 1
)

type data interface {
	toBytes() []byte
}

//Intent contains all data fields of an Intent request or Intent communication
type Intent struct {
	sha3           [sha3Len]byte
	clientUsername string
	clientSNI      string
	serverUsername string
	serverSNI      string
	port           uint16
	actionType     byte
	associatedData string
}

//intentConfirmationMsg contains deadline for an approved auth grant
type intentConfirmationMsg struct {
	deadline int64 //Unix time
}

//intentDeniedMsg contains reason for a denied auth grant
type intentDeniedMsg struct {
	reason string
}

//Constructors
func newIntent(digest [sha3Len]byte, sUser string, hostname string, port string, grantType byte, associatedData string) *Intent {
	user, _ := user.Current()
	cSNI, _ := os.Hostname()
	p, _ := strconv.Atoi(port)

	r := &Intent{
		sha3:           digest,
		clientUsername: user.Username,
		clientSNI:      cSNI,
		serverUsername: sUser,
		serverSNI:      hostname,
		port:           uint16(p),
		actionType:     grantType,
		associatedData: associatedData,
	}
	return r
}

func newIntentRequest(digest [sha3Len]byte, sUser string, hostname string, port string, grantType byte, arg string) *agMessage {
	return &agMessage{
		msgType: IntentRequest,
		d:       newIntent(digest, sUser, hostname, port, grantType, arg),
	}
}

//Makes an Intent Communication from an Intent Request (just change msg type)
func commFromReq(b []byte) []byte {
	return append([]byte{IntentCommunication}, b[:]...)
}

func newIntentConfirmation(t time.Time) *agMessage {
	c := &intentConfirmationMsg{
		deadline: t.Unix(),
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
func (r *Intent) toBytes() []byte {
	s := [irHeaderLen]byte{}
	copy(s[sha3Offset:cUserOffset], r.sha3[:])
	copy(s[cUserOffset:cSNIOffset], []byte(r.clientUsername))
	copy(s[cSNIOffset:sUserOffset], []byte(r.clientSNI))
	copy(s[sUserOffset:sSNIOffset], []byte(r.serverUsername))
	copy(s[sSNIOffset:portOffset], []byte(r.serverSNI))
	binary.BigEndian.PutUint16(s[portOffset:actionTypeOffset], r.port)
	s[actionTypeOffset] = r.actionType
	binary.BigEndian.PutUint16(s[associatedDataLenOffset:associatedDataOffset], uint16(len(r.associatedData)))
	return append(s[:], []byte(r.associatedData)...)
}

func (c *intentConfirmationMsg) toBytes() []byte {
	s := [deadlineLen]byte{}
	binary.BigEndian.PutUint64(s[deadlineOffset:], uint64(c.deadline))
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
func fromIntentBytes(b []byte) *Intent {
	r := Intent{}
	copy(r.sha3[:], b[sha3Offset:cUserOffset])
	r.clientUsername = trimNullBytes(b[cUserOffset:cSNIOffset])
	r.clientSNI = trimNullBytes(b[cSNIOffset:sUserOffset])
	r.serverUsername = trimNullBytes(b[sUserOffset:sSNIOffset])
	r.serverSNI = trimNullBytes(b[sSNIOffset:portOffset])
	r.port = binary.BigEndian.Uint16(b[portOffset:actionTypeOffset])
	r.actionType = b[actionTypeOffset]
	r.associatedData = string(b[associatedDataOffset:])
	return &r
}

func fromIntentRequestBytes(b []byte) *Intent {
	return fromIntentBytes(b[1:])
}

func fromIntentCommunicationBytes(b []byte) *Intent {
	return fromIntentBytes(b[1:])
}

func fromIntentConfirmationBytes(b []byte) *intentConfirmationMsg {
	n := intentConfirmationMsg{}
	n.deadline = int64(binary.BigEndian.Uint64(b[deadlineOffset:]))
	return &n
}

func fromIntentDeniedBytes(b []byte) *intentDeniedMsg {
	d := intentDeniedMsg{}
	d.reason = string(b[reasonOffset:])
	return &d
}

//Address returns the serverSNI and port from the intent
func (r *Intent) Address() (string, string) {
	return r.serverSNI, strconv.Itoa(int(r.port))
}

//Username returns the serverUsername from the intent
func (r *Intent) Username() string {
	return r.serverUsername
}

//Prompt prints the authgrant approval prompt to terminal and continues prompting until user enters "y" or "n"
func (r *Intent) Prompt(reader *io.PipeReader) bool {
	var ans string
	for ans != "y" && ans != "n" {
		if r.actionType == CommandAction {
			fmt.Printf("\nAllow %v@%v to run %v on %v@%v? [y/n]: ",
				r.clientUsername,
				r.clientSNI,
				r.associatedData,
				r.serverUsername,
				r.serverSNI,
			)
		} else if r.actionType == ShellAction {
			fmt.Printf("\nAllow %v@%v to open a default shell on %v@%v? [y/n]: ",
				r.clientUsername,
				r.clientSNI,
				r.serverUsername,
				r.serverSNI,
			)
		} else {
			//TODO: actually parse out details
			fmt.Printf("(\nAllow %v@%v to do local or remote port forwarding with %v@%v? [y/n]: ",
				r.clientUsername,
				r.clientSNI,
				r.serverUsername,
				r.serverSNI,
			)
		}
		scanner := bufio.NewScanner(reader)
		scanner.Scan()
		ans = scanner.Text()
	}
	return ans == "y"
}
