package authgrants

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"

	"hop.computer/hop/core"
)

func TestDelegate(t *testing.T) {
	pc, pcP := net.Pipe() // principal conn
	tc, tcT := net.Pipe() // target conn

	ir1 := getTestCmdIntentRequest(t, "test cmd")

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

	err := StartDelegateInstance(pc, []Intent{ir1.Data.Intent})
	assert.NilError(t, err)
}

func TestDelegateMultipleIRs(t *testing.T) {
	pc, pcP := net.Pipe() // principal conn
	tc, tcT := net.Pipe() // target conn

	ir1 := getTestCmdIntentRequest(t, "cmd1")
	ir2 := getTestCmdIntentRequest(t, "cmd2")
	ir3 := getTestCmdIntentRequest(t, "cmd3")

	ciFunc := func(Intent) error {
		logrus.Info("principal: checking intent")
		return nil
	}

	setupTarg := func(u core.URL) (net.Conn, error) {
		logrus.Infof("target setup: simulating connection to %s", u.String())
		return tc, nil
	}

	// Start "Target"
	go fakeTargetLoop(t, tcT)

	go StartPrincipalInstance(pcP, ciFunc, setupTarg)

	err := StartDelegateInstance(pc, []Intent{ir1.Data.Intent, ir2.Data.Intent, ir3.Data.Intent})
	assert.NilError(t, err)

}
