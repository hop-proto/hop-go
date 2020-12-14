package portal

import (
	"fmt"
	"net"
)

// Addr implements net.Addr for subspace channels
//
// TODO(dadrian): Not sure if we should use this type or not.
type Addr struct {
	SessionID  SessionID
	underlying net.Addr
}

var _ net.Addr = &Addr{}

// Network always returns subspace
func (a *Addr) Network() string {
	return "subspace"
}

// String implements Addr
func (a *Addr) String() string {
	return fmt.Sprintf("subspace://%s@%s", a.SessionID, a.underlying.String())
}
