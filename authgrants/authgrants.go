package authgrants

import (
	"fmt"
	"sync"
	"time"

	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

// PrincipalID identifier used to keep track of granting principal
type PrincipalID uint32

// Authgrant holds just the information needed to be stored on target
type Authgrant struct {
	GrantType      GrantType
	StartTime      time.Time
	ExpTime        time.Time
	DelegateCert   certs.Certificate
	AssociatedData GrantData
	PrincipalID    PrincipalID
}

// AuthgrantMapSync holds current authgrants
type AuthgrantMapSync struct {
	// +checklocks:agLock
	agMap  map[string]map[keys.PublicKey][]Authgrant
	agLock sync.Mutex
}

/*
map[string]map[keys.PublicKey][]Authgrant

{
    "userA": {
        PublicKey1: [Authgrant1, Authgrant2],
        PublicKey2: [Authgrant3]
    },
    "userB": {
        PublicKey3: [Authgrant4, Authgrant5],
        PublicKey4: [Authgrant6]
    }
}
*/

// NewAuthgrantMapSync creates a new map
func NewAuthgrantMapSync() *AuthgrantMapSync {
	return &AuthgrantMapSync{
		agMap:  make(map[string]map[keys.PublicKey][]Authgrant),
		agLock: sync.Mutex{},
	}
}

// AddAuthGrant adds a new authgrant to the map
func (m *AuthgrantMapSync) AddAuthGrant(i *Intent, p PrincipalID) {
	m.agLock.Lock()
	defer m.agLock.Unlock()
	user := i.TargetUsername
	if _, ok := m.agMap[user]; !ok {
		m.agMap[user] = make(map[keys.PublicKey][]Authgrant)
	}
	ag := newAuthgrant(i, p)
	m.agMap[user][i.DelegateCert.PublicKey] = append(m.agMap[user][i.DelegateCert.PublicKey], ag)
}

// RemoveAuthgrants removes and returns authgrants for user:key if they exist
func (m *AuthgrantMapSync) RemoveAuthgrants(user string, key keys.PublicKey) ([]Authgrant, error) {
	m.agLock.Lock()
	defer m.agLock.Unlock()

	if ags, ok := m.agMap[user]; ok { // if user has any authgrants
		if val, ok := ags[key]; ok { // if key has an entry
			delete(ags, key) // remove from server mapping
			return val, nil
		}
	}
	return []Authgrant{}, fmt.Errorf("no authgrant for user %s found for provided key", user)
}

// newAuthgrant returns authgrant built from an intent obj
func newAuthgrant(i *Intent, p PrincipalID) Authgrant {
	return Authgrant{
		GrantType:      i.GrantType,
		StartTime:      i.StartTime,
		ExpTime:        i.ExpTime,
		DelegateCert:   i.DelegateCert,
		AssociatedData: i.AssociatedData,
		PrincipalID:    p,
	}
}
