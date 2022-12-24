package authgrants

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/core"
)

func TestDelegate(t *testing.T) {
	pc, pcP := net.Pipe() // principal conn
	tc, tcT := net.Pipe() // target conn

	ir1 := getTestIntentRequest(t)

	ciFunc := func(Intent) error {
		logrus.Info("principal: checking intent")
		return nil
	}

	setupTarg := func(u core.URL) (net.Conn, error) {
		logrus.Infof("target setup: simulating connection to %s", u.String())
		return tc, nil
	}

	// Start "Target"
	go fakeTarget(t, tcT)

	go StartPrincipalInstance(pcP, ciFunc, setupTarg)

	StartDelegateInstance(pc, []Intent{ir1.Data.Intent})

}
