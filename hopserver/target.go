package hopserver

import (
	"fmt"
	"time"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
	"hop.computer/hop/tubes"
)

// Target server: a hop server that a delegate hop client
// wishes to perform an action(s) on under the authority of a
// principal hop client.
// Responsibilities [status]:
// - receive and approve / deny "Intent Communication" messages from principals [implemented]
// - maintain a mapping of current authgrants [implemented, removing expired still TODO]
// - keep server authkey store up to date (add / remove) [adding implemented, removing TODO]
// - conducting user authorization with authgrants
// - checking all client actions if authorized using an authgrant and updating
//   authorized actions accordingly

// type authgrant struct {
// 	Data authgrants.AuthGrantData // relevant data from IR
// 	// Principal *hopSession
// 	principalID principalID
// }

func (s *HopServer) authorizeKeyAuthGrant(user string, publicKey keys.PublicKey) ([]authgrants.Authgrant, error) {
	if s.config.AllowAuthgrants != nil && *s.config.AllowAuthgrants {
		return s.agMap.RemoveAuthgrants(user, publicKey)
	}
	return []authgrants.Authgrant{}, fmt.Errorf("auth grants not enabled")
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
	sess.server.agMap.AddAuthGrant(&intent, authgrants.PrincipalID(sess.ID))

	//add delegate key from cert to transport server authorized key pool
	sess.server.keyStore.AddKey(intent.DelegateCert.PublicKey)

	// fine grained
	return authgrants.MessageData{}, true
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
func (sess *hopSession) checkCmd(cmd string) (sessID, error) {
	for i, ag := range sess.authorizedActions {
		if time.Now().Before(ag.ExpTime) && ag.GrantType == authgrants.Command {
			if ag.AssociatedData.CommandGrantData.Cmd == cmd {
				// remove from authorized actions and return
				sess.authorizedActions = append(sess.authorizedActions[:i], sess.authorizedActions[i+1:]...)
				return sessID(ag.PrincipalID), nil
			}
		}
	}
	return 0, fmt.Errorf("no auth grant for cmd: %s", cmd)
}
