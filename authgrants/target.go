package authgrants

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
)

// logic for a hop server receiving an intent comm and approving or
// denying

type addAuthGrantFunc func(*Intent) error

type targetInstance struct {
	principalConn net.Conn

	checkIntent  checkIntentFunc
	addAuthGrant addAuthGrantFunc
}

// StartTargetInstance creates and runs a new target instance
func StartTargetInstance(pc net.Conn, ci checkIntentFunc, f addAuthGrantFunc) error {
	defer pc.Close()

	ti := targetInstance{
		principalConn: pc,
		checkIntent:   ci,
		addAuthGrant:  f,
	}

	if ci == nil {
		ti.checkIntent = defaultRejectAll
	}

	ti.run()
	return nil
}

func (t *targetInstance) run() {
	for {
		err := t.handleIntentCommunication()
		if err != nil {
			logrus.Errorf("target: error handling intent communication: %v", err.Error())
			return
		}
	}
}

func (t *targetInstance) handleIntentCommunication() error {
	i, err := ReadIntentCommunication(t.principalConn)
	if err != nil {
		logrus.Errorf("target: error reading intent communication: %v", err)
		return fmt.Errorf("target: error reading intent communication: %s", err)
	}
	logrus.Info("target: read intent communication")
	err = t.checkIntent(i)
	if err != nil {
		logrus.Error("target: error checking intent: ", err)
		return WriteIntentDenied(t.principalConn, err.Error())
	}
	logrus.Info("target: finished checking intent")
	err = t.addAuthGrant(&i)
	if err != nil {
		logrus.Error("target: error adding authgrant")
		return WriteIntentDenied(t.principalConn, err.Error())
	}
	return WriteIntentConfirmation(t.principalConn)
}
