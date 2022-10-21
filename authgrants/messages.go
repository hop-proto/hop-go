package authgrants

import "hop.computer/hop/certs"

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

// AgMessage Type || Data
type AgMessage struct {
	MsgType msgType
	Data    any
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
	StartTime      int64
	ExpTime        int64
	TargetSNI      certs.Name
	TargetUsername string
	DelegateCert   []byte
	AssociatedData GrantData
}

// Denial is the body of an IntentDenied message (contains an optional reason)
type Denial struct {
	Reason string
}

// TODO(baumanl): not sure if this is the best way to approach this.
// For shell/cmd access not much additional data is needed. Port forwarding
// may require more --> once this is implemented should inform the design
// decision here.

// GrantData is an interface for Intent Associated data for diff grant types
type GrantData interface {
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
func NewAuthGrantMessage(t msgType, data any) AgMessage {
	return AgMessage{t, data}
}
