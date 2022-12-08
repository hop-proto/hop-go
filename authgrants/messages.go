package authgrants

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"hop.computer/hop/certs"
	"hop.computer/hop/common"
	"hop.computer/hop/core"
)

// Authgrant Message Types:
// IntentRequest: Delegate -> Principal
// IntentCommunication: Principal -> Target
// IntentConfirmation/IntentDenied: Target -> Principal and/or Principal -> Delegate
const (
	IntentRequest       = msgType(1)
	IntentCommunication = msgType(2)
	IntentConfirmation  = msgType(3)
	IntentDenied        = msgType(4)
)

type msgType byte

// MessageData represents either intent or denial reason
type MessageData struct {
	Intent Intent
	Denial string
}

// TargetDenial reason msg for when Target has policy against authgrants
const TargetDenial = "Authgrants not enabled on target server."

// MalformedIntentDen reason msg fro when the intent request is malformed
const MalformedIntentDen = "Malformed intent request"

// UnexpectedMessageType reason msg for when the expected intent msg is not a communication message
const UnexpectedMessageType = "Unexpected message type"

// UnrecognizedGrantType reason msg for when the grant type is not known by the target
const UnrecognizedGrantType = "Unrecognized grant type"

// AgMessage Type || Data
type AgMessage struct {
	MsgType msgType
	Data    MessageData // TODO(baumanl): what interface? inc: Intent, Denial
}

// Grant Type Constants
const (
	Shell    = GrantType(1)
	Command  = GrantType(2)
	LocalPF  = GrantType(3)
	RemotePF = GrantType(4)
)

// GrantType differentiates between types of actions
type GrantType byte

// Intent contains body of an Intent Request or Intent Communication
type Intent struct {
	GrantType      GrantType
	Reserved       byte
	TargetPort     uint16
	StartTime      time.Time
	ExpTime        time.Time
	TargetSNI      certs.Name
	TargetUsername string
	DelegateCert   certs.Certificate
	AssociatedData GrantData
}

// TODO(baumanl): not sure if this is the best way to approach this.
// For shell/cmd access not much additional data is needed. Port forwarding
// may require more --> once this is implemented should inform the design
// decision here.

// GrantData is a struct for Intent Associated data for diff grant types
type GrantData struct {
	ShellGrantData    ShellGrantData
	CommandGrantData  CommandGrantData
	LocalPFGrantData  LocalPFGrantData
	RemotePFGrantData RemotePFGrantData
}

// ShellGrantData info needed for authgrant for shell access
type ShellGrantData struct {
}

// CommandGrantData info needed for authgrant for executing a cmd
type CommandGrantData struct {
	Cmd string
}

// LocalPFGrantData info for local pf authgrant
type LocalPFGrantData struct {
}

// RemotePFGrantData info for remote pf authgrant
type RemotePFGrantData struct {
}

// NewAuthGrantMessage makes an agMessage with type and data
func NewAuthGrantMessage(t msgType, data MessageData) AgMessage {
	return AgMessage{t, data}
}

// WriteTo serializes an authgrant message and implements the io.WriterTo interface
func (m *AgMessage) WriteTo(w io.Writer) (int64, error) {
	var written int64
	// write message type
	n, err := w.Write([]byte{byte(m.MsgType)})
	written += int64(n)
	if err != nil {
		return written, err
	}
	// write message data
	var dataLen int64
	switch m.MsgType {
	case IntentRequest:
		dataLen, err = m.Data.Intent.WriteTo(w)
	case IntentCommunication:
		dataLen, err = m.Data.Intent.WriteTo(w)
	case IntentConfirmation:
		dataLen = 0
	case IntentDenied:
		dataLen, err = common.WriteString(m.Data.Denial, w)
	}
	written += dataLen
	if err != nil {
		return written, err
	}
	return written, nil
}

// ReadFrom reads a serialized ag msg
func (m *AgMessage) ReadFrom(r io.Reader) (int64, error) {
	var bytesRead int64
	// read message type
	err := binary.Read(r, binary.BigEndian, &m.MsgType)
	if err != nil {
		return bytesRead, err
	}
	bytesRead++
	// read message data
	var dataBytes int64
	switch m.MsgType {
	case IntentRequest:
		dataBytes, err = m.Data.Intent.ReadFrom(r)
	case IntentCommunication:
		dataBytes, err = m.Data.Intent.ReadFrom(r)
	case IntentDenied:
		m.Data.Denial, dataBytes, err = common.ReadString(r)
	}

	bytesRead += dataBytes
	if err != nil {
		return bytesRead, err
	}
	return bytesRead, nil
}

// WriteTo serializes an intent block and implements the io.WriterTo interface
func (i *Intent) WriteTo(w io.Writer) (int64, error) {
	var written int64
	// write grantType and reserved byte
	n, err := w.Write([]byte{byte(i.GrantType), i.Reserved})
	written += int64(n)
	if err != nil {
		return written, err
	}
	// write target port
	err = binary.Write(w, binary.BigEndian, i.TargetPort)
	if err != nil {
		return written, err
	}
	written += 2
	// write start time
	err = binary.Write(w, binary.BigEndian, i.StartTime.Unix())
	if err != nil {
		return written, err
	}
	written += 8
	// write exp time
	err = binary.Write(w, binary.BigEndian, i.ExpTime.Unix())
	if err != nil {
		return written, err
	}
	written += 8
	// write targetSNI
	targetSNILen, err := i.TargetSNI.WriteTo(w)
	written += targetSNILen
	if err != nil {
		return written, err
	}
	// write targetUsername
	usernameLen, err := common.WriteString(i.TargetUsername, w)
	written += usernameLen
	if err != nil {
		return written, err
	}
	// write delegateCert
	delegateCertLen, err := i.DelegateCert.WriteTo(w)
	written += delegateCertLen
	if err != nil {
		return written, err
	}
	// write all associated data
	var assocDataLen int64
	switch i.GrantType {
	case Command:
		assocDataLen, err = i.AssociatedData.CommandGrantData.WriteTo(w)
	case Shell:
		assocDataLen, err = i.AssociatedData.ShellGrantData.WriteTo(w)
	case LocalPF:
		assocDataLen, err = i.AssociatedData.LocalPFGrantData.WriteTo(w)
	case RemotePF:
		assocDataLen, err = i.AssociatedData.RemotePFGrantData.WriteTo(w)
	}
	written += assocDataLen
	if err != nil {
		return written, err
	}

	return written, nil
}

// ReadFrom reads a serialized intent block
func (i *Intent) ReadFrom(r io.Reader) (int64, error) {
	var bytesRead int64
	// read grantType and reserved byte
	err := binary.Read(r, binary.BigEndian, &i.GrantType)
	if err != nil {
		return bytesRead, err
	}
	bytesRead++

	err = binary.Read(r, binary.BigEndian, &i.Reserved)
	if err != nil {
		return bytesRead, err
	}
	bytesRead++
	// read target port
	err = binary.Read(r, binary.BigEndian, &i.TargetPort)
	if err != nil {
		return bytesRead, err
	}
	bytesRead += 2

	// read start time
	var t uint64
	err = binary.Read(r, binary.BigEndian, &t)
	if err != nil {
		return bytesRead, err
	}
	if t > math.MaxInt64 {
		return bytesRead, errors.New("start timestamp too large")
	}
	bytesRead += 8
	i.StartTime = time.Unix(int64(t), 0)
	// read exp time
	err = binary.Read(r, binary.BigEndian, &t)
	if err != nil {
		return bytesRead, err
	}
	if t > math.MaxInt64 {
		return bytesRead, errors.New("exp timestamp too large")
	}
	bytesRead += 8
	i.ExpTime = time.Unix(int64(t), 0)
	// read targetSNI
	n, err := i.TargetSNI.ReadFrom(r)
	if err != nil {
		return bytesRead, err
	}
	bytesRead += n
	// read targetUsername
	username, usernameBytes, err := common.ReadString(r)
	if err != nil {
		return bytesRead, err
	}
	bytesRead += usernameBytes
	i.TargetUsername = username
	// read delegateCert
	certBytes, err := i.DelegateCert.ReadFrom(r)
	if err != nil {
		return bytesRead, err
	}
	bytesRead += certBytes
	// read all associatedData
	var assocDataBytes int64
	switch i.GrantType {
	case Command:
		assocDataBytes, err = i.AssociatedData.CommandGrantData.ReadFrom(r)
	case Shell:
		assocDataBytes, err = i.AssociatedData.ShellGrantData.ReadFrom(r)
	case LocalPF:
		assocDataBytes, err = i.AssociatedData.LocalPFGrantData.ReadFrom(r)
	case RemotePF:
		assocDataBytes, err = i.AssociatedData.RemotePFGrantData.ReadFrom(r)
	}

	if err != nil {
		return bytesRead, err
	}
	bytesRead += assocDataBytes
	return bytesRead, nil
}

// WriteTo serializes command grant data  and implements the io.WriterTo interface
func (d *CommandGrantData) WriteTo(w io.Writer) (int64, error) {
	return common.WriteString(d.Cmd, w)
}

// ReadFrom reads a serialized commandgrantdata block
func (d *CommandGrantData) ReadFrom(r io.Reader) (int64, error) {
	// read command
	cmd, cmdBytes, err := common.ReadString(r)
	d.Cmd = cmd
	return cmdBytes, err

}

// WriteTo writes serialized shell grant data
func (d *ShellGrantData) WriteTo(w io.Writer) (int64, error) {
	panic("unimplemented")
}

// ReadFrom reads a serialized commandgrantdata block
func (d *ShellGrantData) ReadFrom(r io.Reader) (int64, error) {
	// read command
	panic("unimplemented")
}

// WriteTo writes serialized local pf grant data
func (d *LocalPFGrantData) WriteTo(w io.Writer) (int64, error) {
	panic("unimplemented")
}

// ReadFrom reads a serialized commandgrantdata block
func (d *LocalPFGrantData) ReadFrom(r io.Reader) (int64, error) {
	// read command
	panic("unimplemented")
}

// WriteTo writes serialized remote pf grant data
func (d *RemotePFGrantData) WriteTo(w io.Writer) (int64, error) {
	panic("unimplemented")
}

// ReadFrom reads a serialized commandgrantdata block
func (d *RemotePFGrantData) ReadFrom(r io.Reader) (int64, error) {
	// read command
	panic("unimplemented")
}

// ReadIntentRequest reads intent request and returns intent
func ReadIntentRequest(r io.Reader) (Intent, error) {
	var m AgMessage
	_, err := m.ReadFrom(r)
	if err != nil {
		return m.Data.Intent, err
	}
	if m.MsgType != IntentRequest {
		return m.Data.Intent, fmt.Errorf("expected msg type of Intent Request. Got %v", m.MsgType)
	}
	return m.Data.Intent, nil
}

// ReadConfOrDenial reads an authgrant message and errors if it is not conf or denial
func ReadConfOrDenial(r io.Reader) (AgMessage, error) {
	var m AgMessage
	_, err := m.ReadFrom(r)
	if err != nil {
		return m, err
	}
	if m.MsgType != IntentDenied && m.MsgType != IntentConfirmation {
		return m, fmt.Errorf("received unexpected msg type")
	}
	return m, nil
}

// SendIntentDenied sends intent denied message with reason
func SendIntentDenied(w io.Writer, reason string) error {
	m := AgMessage{
		MsgType: IntentDenied,
		Data: MessageData{
			Denial: reason,
		},
	}
	_, err := m.WriteTo(w)
	return err
}

// SendIntentConfirmation sends intent confirmation
func SendIntentConfirmation(w io.Writer) error {
	m := AgMessage{
		MsgType: IntentConfirmation,
	}
	_, err := m.WriteTo(w)
	return err
}

// SendIntentCommunication sends intent communication messages
func SendIntentCommunication(w io.Writer, i Intent) error {
	m := AgMessage{
		MsgType: IntentCommunication,
		Data: MessageData{
			Intent: i,
		},
	}
	_, err := m.WriteTo(w)
	return err
}

// TargetURL gives url of target of intent
func (i Intent) TargetURL() *core.URL {
	return &core.URL{
		User: i.TargetUsername,
		Host: string(i.TargetSNI.Label),
		Port: fmt.Sprint(i.TargetPort),
	}
}
