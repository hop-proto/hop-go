package authgrants

import (
	"encoding/binary"
	"io"
	"time"

	"hop.computer/hop/certs"
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

// MessageData interface describes what the data field of ag msg can do
type MessageData interface {
	io.WriterTo
	io.ReaderFrom
}

// AgMessage Type || Data
type AgMessage struct {
	MsgType msgType
	Data    MessageData // TODO(baumanl): what interface? inc: Intent, Denial
}

// Grant Type Constants
const (
	Shell    = grantType(1)
	Command  = grantType(2)
	LocalPF  = grantType(3)
	RemotePF = grantType(4)
)

type grantType byte

// Intent contains body of an Intent Request or Intent Communication
type Intent struct {
	GrantType      grantType
	Reserved       byte
	TargetPort     uint16
	StartTime      time.Time
	ExpTime        time.Time
	TargetSNI      certs.Name
	TargetUsername string
	DelegateCert   certs.Certificate
	AssociatedData GrantData
}

// Denial is the body of an IntentDenied message (contains an optional reason)
// TODO: does this struct need other info? or just use a raw string
type Denial struct {
	Reason string
}

// TODO(baumanl): not sure if this is the best way to approach this.
// For shell/cmd access not much additional data is needed. Port forwarding
// may require more --> once this is implemented should inform the design
// decision here.

// GrantData is an interface for Intent Associated data for diff grant types
type GrantData interface {
	io.WriterTo
	io.ReaderFrom
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
	dataLen, err := m.Data.WriteTo(w)
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
	// read message data
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
	usernameLen, err := writeString(i.TargetUsername, w)
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
	assocDataLen, err := i.AssociatedData.WriteTo(w)
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
	// read target port
	// read start time
	// read exp time
	// read targetSNI
	// read targetUsername
	// read delegateCert
	// read all associatedData
	return bytesRead, nil
}

// helper function to write a string preceded by its length.
func writeString(s string, w io.Writer) (int64, error) {
	var written int64
	nameLen := uint32(len(s)) //?
	err := binary.Write(w, binary.BigEndian, nameLen)
	if err != nil {
		return written, err
	}
	written += 4
	n, err := w.Write([]byte(s))
	written += int64(n)
	if err != nil {
		return written, err
	}
	return written, nil
}

// helper function that reads a string
func readString(r io.Reader) string {
	panic("unimplemented")
	// read len
	// read string
}

// WriteTo serializes a denial msg and implements the io.WriterTo interface
func (d *Denial) WriteTo(w io.Writer) (int64, error) {
	return writeString(d.Reason, w)
}

// ReadFrom reads a serialized denial block
func (d *Denial) ReadFrom(r io.Reader) (int64, error) {
	// read denial reason
	readString(r)
	panic("unimplemented")
}

// WriteTo serializes command grant data  and implements the io.WriterTo interface
func (d *CommandGrantData) WriteTo(w io.Writer) (int64, error) {
	return writeString(d.Cmd, w)
}

// ReadFrom reads a serialized commandgrantdata block
func (d *CommandGrantData) ReadFrom(r io.Reader) (int64, error) {
	// read command
	panic("unimplemented")
}

// WriteTo writes serialized shell grant data
func (d *ShellGrantData) WriteTo(w io.Writer) (int64, error) {
	panic("unimplemented")
}

// WriteTo writes serialized local pf grant data
func (d *LocalPFGrantData) WriteTo(w io.Writer) (int64, error) {
	panic("unimplemented")
}

// WriteTo writes serialized remote pf grant data
func (d *RemotePFGrantData) WriteTo(w io.Writer) (int64, error) {
	panic("unimplemented")
}
