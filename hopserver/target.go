package hopserver

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/keys"
)

// Target server: a hop server that a delegate hop client
// wishes to perform an action(s) on under the authority of a
// principal hop client.
// Responsibilities [status]:
// - receive and approve / deny "Intent Communication" messages from principals [implemented]
// - maintain a mapping of current authgrants [implemented, removing expired still TODO]
// - keep server authkey store up to date (add / remove)
// - conducting user authorization with authgrants
// - checking all client actions if authorized using an authgrant and updating
//   authorized actions accordingly

func (s *HopServer) authorizeKeyAuthGrant(user string, publicKey keys.PublicKey) ([]authgrants.Authgrant, error) {
	if s.config.EnableAuthgrants != nil && *s.config.EnableAuthgrants {
		ags, err := s.agMap.RemoveAuthgrants(user, publicKey)
		if err == nil {
			// remove from transport layer key set
			s.keyStore.RemoveKey(publicKey)
		}
		return ags, err
	}
	return []authgrants.Authgrant{}, fmt.Errorf("auth grants not enabled")
}

func (sess *hopSession) addAuthGrant(intent *authgrants.Intent) error {
	if intent == nil {
		logrus.Error("intent is nil")
		return fmt.Errorf("intent is nil")
	}

	if sess.server == nil {
		return fmt.Errorf("server is nil")
	}

	if sess.server.agMap == nil {
		return fmt.Errorf("agmap is nil")
	}

	if sess.server.keyStore == nil {
		return fmt.Errorf("keystore is nil")
	}

	// add authorization grant to server mappings
	sess.server.agMap.AddAuthGrant(intent, authgrants.PrincipalID(sess.ID))

	// add delegate key from cert to transport server authorized key pool
	sess.server.keyStore.AddKey(intent.DelegateCert.PublicKey)

	return nil
}

// checkIntent looks at details of Intent Request and ensures they follow its policies
// func (sess *hopSession) checkIntent(tube *tubes.Reliable) (authgrants.MessageData, bool) {
func (sess *hopSession) checkIntent(intent authgrants.Intent, principalCert *certs.Certificate) error {
	// check that requested time is valid
	if intent.ExpTime.Before(time.Now()) {
		return fmt.Errorf("invalid expiration time")
	}

	// TODO(baumanl): check target SNI matches the current hostname of this server? necessary?

	// check target username matches current username that client
	// logged in as.
	if sess.user != intent.TargetUsername {
		return fmt.Errorf("current user and requested user mismatch")
	}

	// check that DelegateCert is well formatted
	if err := certs.VerifyLeafFormat(&intent.DelegateCert, certs.VerifyOptions{}); err != nil {
		return fmt.Errorf("ill-formatted delegate certificate")
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
		return fmt.Errorf(authgrants.UnrecognizedGrantType)
	}
	return nil
}

// TODO(baumanl): rewrite this/think about best way to generalize to all grant types
// checks if the session has an auth grant to perform cmd
func (sess *hopSession) checkCmd(cmd string, shell bool) (sessID, error) {
	logrus.Info("target: received request to perform: ", cmd)
	for i, ag := range sess.authorizedActions {
		if time.Now().Before(ag.ExpTime) {
			if !shell && ag.GrantType == authgrants.Command {
				if ag.AssociatedData.CommandGrantData.Cmd == cmd {
					// remove from authorized actions and return
					sess.authorizedActions = append(sess.authorizedActions[:i], sess.authorizedActions[i+1:]...)
					return sessID(ag.PrincipalID), nil
				}
			}
			if shell && ag.GrantType == authgrants.Shell {
				sess.authorizedActions = append(sess.authorizedActions[:i], sess.authorizedActions[i+1:]...)
				return sessID(ag.PrincipalID), nil
			}
		}
	}
	return 0, fmt.Errorf("no auth grant for cmd: %s", cmd)
}
