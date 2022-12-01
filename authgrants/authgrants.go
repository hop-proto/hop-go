package authgrants

import (
	"time"

	"hop.computer/hop/certs"
)

// AuthGrantData holds just the information needed to be stored on target
type AuthGrantData struct {
	GrantType      GrantType
	StartTime      time.Time
	ExpTime        time.Time
	DelegateCert   certs.Certificate
	AssociatedData GrantData
}

// GetData returns AuthGrantData pulled from an intent obj
func (i *Intent) GetData() AuthGrantData {
	return AuthGrantData{
		GrantType:      i.GrantType,
		StartTime:      i.StartTime,
		ExpTime:        i.ExpTime,
		DelegateCert:   i.DelegateCert,
		AssociatedData: i.AssociatedData,
	}
}
