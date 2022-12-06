package hopserver

import (
	"fmt"
	"sync"
	"time"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/tubes"
)

type authgrant struct {
	Data      authgrants.AuthGrantData // relevant data from IR
	Principal *hopSession
}

type authgrantMapSync struct {
	authgrants map[string]map[keys.PublicKey][]authgrant
	agLock     sync.Mutex
}

func newAuthgrantMapSync() *authgrantMapSync {
	return &authgrantMapSync{
		authgrants: make(map[string]map[keys.PublicKey][]authgrant),
		agLock:     sync.Mutex{},
	}
}

func (s *HopServer) authorizeKeyAuthGrant(user string, publicKey keys.PublicKey) ([]authgrant, error) {
	if s.config.AllowAuthgrants != nil && *s.config.AllowAuthgrants {
		return s.agMap.getAuthgrants(user, publicKey)
	}
	return []authgrant{}, fmt.Errorf("auth grants not enabled")
}

func (m *authgrantMapSync) getAuthgrants(user string, key keys.PublicKey) ([]authgrant, error) {
	m.agLock.Lock()
	defer m.agLock.Unlock()

	if ags, ok := m.authgrants[user]; ok { // if user has any authgrants
		if val, ok := ags[key]; ok { // if key has an entry
			delete(ags, key) // remove from server mapping
			// TODO(baumanl): add check to remove from transport keyStore
			return val, nil
		}
	}
	return []authgrant{}, fmt.Errorf("no authgrant for user %s found for provided key", user)
}

// checkIntent looks at details of Intent Request and ensures they follow its policies
func (sess *hopSession) checkIntent(tube *tubes.Reliable) (authgrants.MessageData, bool) {
	// read intent:
	var ir authgrants.AgMessage
	_, err := ir.ReadFrom(tube)
	if err != nil {
		return authgrants.MessageData{Denial: authgrants.MalformedIntentDen}, false
	}
	// check that msg type is correct
	if ir.MsgType != authgrants.IntentCommunication {
		return authgrants.MessageData{Denial: authgrants.UnexpectedMessageType}, false
	}
	intent := ir.Data.Intent

	// check that requested time is valid
	if intent.ExpTime.Before(time.Now()) {
		return authgrants.MessageData{Denial: "invalid expiration time"}, false
	}

	// TODO(baumanl): check target SNI matches the current hostname of this server? necessary?

	// check target username matches current username that client
	// logged in as.
	if sess.user != intent.TargetUsername {
		return authgrants.MessageData{Denial: "Current user and requested user mismatch"}, false
	}

	// check that DelegateCert is well formatted
	if err = certs.VerifyLeafFormat(&intent.DelegateCert, certs.VerifyOptions{}); err != nil {
		return authgrants.MessageData{Denial: "Ill-formatted delegate certificate"}, false
	}
	// TODO(baumanl): add in finer grained policy checks/options? i.e. account level access control
	// TODO(baumanl): enable fine grained checks based on config options
	// pass the intent to handlers for each type of authgrant
	switch intent.GrantType {
	case authgrants.Shell:
		// TODO(baumanl)
	case authgrants.Command:
		// TODO
	case authgrants.LocalPF:
		// TODO
	case authgrants.RemotePF:
		// TODO
	default:
		return authgrants.MessageData{Denial: authgrants.UnrecognizedGrantType}, false

	}

	// add authorization grant to server mappings
	sess.server.agMap.addAuthGrant(&intent, sess)

	//add delegate key from cert to transport server authorized key pool
	sess.server.keyStore.AddKey(intent.DelegateCert.PublicKey)

	// fine grained
	return authgrants.MessageData{}, true
}

func (m *authgrantMapSync) addAuthGrant(intent *authgrants.Intent, principalSess *hopSession) {
	m.agLock.Lock()
	defer m.agLock.Unlock()
	user := intent.TargetUsername
	m.authgrants[user] = make(map[keys.PublicKey][]authgrant)
	ag := authgrant{
		Data:      intent.GetData(),
		Principal: principalSess,
	}
	m.authgrants[user][intent.DelegateCert.PublicKey] = append(m.authgrants[user][intent.DelegateCert.PublicKey], ag)
}

// TODO(baumanl): how should expired authgrants be removed?
// 1. how often or at what trigger
// 2. when should key be removed from transport keyStore?
// currently never...expired ones are just ignored

// func (s *HopServer) agCleanup() {
// 	s.agLock.Lock()
// 	defer s.agLock.Unlock()
// 	for _, ps := range s.authgrants {
// 		for k, ags := range ps {
// 			del := true
// 			for _, ag := range ags {
// 				if !ag.Data.ExpTime.Before(time.Now()) {
// 					del = false
// 					break
// 				}
// 			}
// 			if del {
// 				delete(ps, k)
// 				s.keyStore.RemoveKey(k)
// 			}

// 		}
// 	}
// }

// checks if the session has an auth grant to perform cmd
func (sess *hopSession) checkCmd(cmd string) (*hopSession, error) {
	for i, ag := range sess.authorizedActions {
		intent := ag.Data
		if time.Now().Before(intent.ExpTime) && intent.GrantType == authgrants.Command {
			if intent.AssociatedData.CommandGrantData.Cmd == cmd {
				sess.authorizedActions = append(sess.authorizedActions[:i], sess.authorizedActions[i+1:]...)
				return ag.Principal, nil
			}
		}
	}
	return nil, fmt.Errorf("no auth grant for cmd: %s", cmd)
}
