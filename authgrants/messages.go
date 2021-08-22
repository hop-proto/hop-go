package authgrants

import (
	"bytes"
	"encoding/binary"
	"errors"
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

	TypeLen = 1
)

//Action Type Constants
const (
	shellTube   = byte(1)
	commandTube = byte(2)
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

//Intent contains all data fields of an Intent request or Intent communication
type Intent struct {
	sha3           [sha3Len]byte
	clientUsername string
	clientSNI      string
	serverUsername string
	serverSNI      string
	port           uint16
	tubeType       byte //default shell or specific command
	action         string
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
func newIntent(digest [sha3Len]byte, sUser string, hostname string, port string, shell bool, cmd string) *Intent {
	user, _ := user.Current()
	cSNI, _ := os.Hostname()
	p, _ := strconv.Atoi(port)

	tt := commandTube
	if shell {
		tt = shellTube
	}

	r := &Intent{
		sha3:           digest,
		clientUsername: user.Username,
		clientSNI:      cSNI,
		serverUsername: sUser,
		serverSNI:      hostname,
		port:           uint16(p),
		tubeType:       tt, //TODO(baumanl): Using to differentiate between asking for shell (run using login(1)) or a specific command
		action:         cmd,
	}
	return r
}

func newIntentRequest(digest [sha3Len]byte, sUser string, hostname string, port string, shell bool, cmd string) *agMessage {
	return &agMessage{
		msgType: IntentRequest,
		d:       newIntent(digest, sUser, hostname, port, shell, cmd),
	}
}

//Makes an Intent Communication from an Intent Request (just change msg type)
func commFromReq(b []byte) []byte {
	return append([]byte{IntentCommunication}, b[TypeLen:]...)
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
	binary.BigEndian.PutUint16(s[portOffset:tTypeOffset], r.port)
	s[tTypeOffset] = r.tubeType
	s[lenOffset] = byte(len(r.action)) //TODO(baumanl): This only allows for actions up to 256 bytes (and no bounds checking atm)
	return append(s[:], []byte(r.action)...)
}

func (c *intentConfirmationMsg) toBytes() []byte {
	s := [intentConfSize]byte{}
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
	r.port = binary.BigEndian.Uint16(b[portOffset:tTypeOffset])
	r.tubeType = b[tTypeOffset]
	r.action = string(b[actOffset:])
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

func (c *AuthGrantConn) readIntent(msgType byte) ([]byte, error) {
	t := make([]byte, 1)
	_, err := c.conn.Read(t)
	if err != nil {
		return nil, err
	}
	if t[0] == msgType {
		irh := make([]byte, irHeaderLen)
		_, err = c.conn.Read(irh)
		if err != nil {
			return nil, err
		}
		actionLen := int8(irh[irHeaderLen-1])
		action := make([]byte, actionLen)
		_, err = c.conn.Read(action)
		if err != nil {
			return nil, err
		}
		return append(t, append(irh, action...)...), nil
	}
	return nil, errors.New("bad msg type")
}

//ReadIntentDenied gets the reason for denial
func (c *AuthGrantConn) readIntentDenied() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = IntentDenied
	_, err := c.conn.Read(buf[1:])
	if err != nil {
		return nil, err
	}
	buf = append(buf, make([]byte, int(buf[1]))...)
	_, err = c.conn.Read(buf[2:])
	if err != nil {
		return nil, err
	}
	return buf, nil
}

//ReadIntentConf
func (c *AuthGrantConn) readIntentConf() ([]byte, error) {
	buf := make([]byte, intentConfSize+1)
	buf[0] = IntentConfirmation
	_, err := c.conn.Read(buf[1:])
	return buf, err
}

//ReadIntentRequest gets Intent Request bytes
func (c *AuthGrantConn) ReadIntentRequest() ([]byte, error) {
	return c.readIntent(IntentRequest)
}

func (c *AuthGrantConn) readIntentCommunication() ([]byte, error) {
	return c.readIntent(IntentCommunication)
}

//SendIntentDenied writes an intent denied message to provided tube
func (c *AuthGrantConn) SendIntentDenied(reason string) error {
	_, err := c.conn.Write(newIntentDenied(reason).toBytes())
	return err
}

//SendIntentConf writes an intent conf message to provided tube
func (c *AuthGrantConn) SendIntentConf(t time.Time) error {
	_, err := c.conn.Write(newIntentConfirmation(t).toBytes())
	return err
}

//SendIntentRequest writes an intent request msg
func (c *AuthGrantConn) sendIntentRequest(digest [sha3Len]byte, sUser string, hostname string, port string, shell bool, cmd string) error {
	_, err := c.conn.Write(newIntentRequest(digest, sUser, hostname, port, shell, cmd).toBytes())
	return err
}

//SendIntentCommunication writes an intent communication msg
func (c *AuthGrantConn) SendIntentCommunication(intentData *Intent) error {
	_, err := c.conn.Write(commFromReq(intentData.toBytes()))
	return err
}

func (c *AuthGrantConn) WriteRawBytes(data []byte) error {
	_, err := c.conn.Write(data)
	return err
}

func (c *AuthGrantConn) GetIntentRequest() (*Intent, error) {
	intentBytes, err := c.ReadIntentRequest()
	if err != nil {
		return nil, err
	}
	return fromIntentRequestBytes(intentBytes), nil
}

func (i *Intent) Address() (string, string) {
	return i.serverSNI, strconv.Itoa(int(i.port))
}

func (i *Intent) Username() string {
	return i.serverUsername
}
