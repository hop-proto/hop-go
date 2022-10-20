package authgrants

import "hop.computer/hop/certs"

// Authgrant Mmessage: Type || Data
type agMessage struct { //nolint
	MsgType byte
	Data    *byte
}

// Authgrant Message Types:
// IntentRequest: Delegate -> Principal
// IntentCommunication: Principal -> Target
// IntentConfirmation/IntentDenied: Target -> Principal and/or Principal -> Delegate
const (
	IntentRequest       = byte(1)
	IntentCommunication = byte(2)
	IntentConfirmation  = byte(3)
	IntentDenied        = byte(4)
)

// Action Type Constants
const (
	ShellAction    = byte(1)
	CommandAction  = byte(2)
	LocalPFAction  = byte(3)
	RemotePFAction = byte(4)
)

type grantType byte

// Intent contains all data fields of an Intent Request or Intent Communication
type Intent struct {
	GrantType      grantType
	Reserved       byte
	TargetPort     uint16
	StartTime      int64
	ExpTime        int64
	TargetUsername string
	TargetSNI      certs.Name
	DelegateCert   []byte
	AssociatedData []byte
}
