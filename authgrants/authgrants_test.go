package authgrants

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"

	"hop.computer/hop/core"
)

func TestFlow(t *testing.T) {
	pc, pcP := net.Pipe() // principal conn (delegate, principal)
	tc, tcT := net.Pipe() // target conn (delegate, target)

	ir1 := getTestCmdIntentRequest(t, "cmd1")
	ir2 := getTestCmdIntentRequest(t, "cmd2")
	ir3 := getTestCmdIntentRequest(t, "cmd3")

	ciFuncPrincipal := func(Intent) error {
		logrus.Info("principal: checking intent")
		return nil
	}

	ciFuncTarget := func(i Intent) error {
		logrus.Info("target: checking intent")
		if i.AssociatedData.CommandGrantData.Cmd == "cmd2" {
			return fmt.Errorf("no auth grants for cmd2")
		}
		return nil
	}

	setupTarg := func(u core.URL) (net.Conn, error) {
		logrus.Infof("simulating connection to %s", u.String())
		return tc, nil
	}

	correctApprovals := []string{"cmd1", "cmd3"}
	approved := []string{}

	addag := func(i *Intent) error {
		logrus.Infof("target: adding ag for %s", i.TargetUsername)
		approved = append(approved, i.AssociatedData.CommandGrantData.Cmd)
		return nil
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		StartTargetInstance(tcT, ciFuncTarget, addag)
		wg.Done()
	}()

	go func() {
		StartPrincipalInstance(pcP, ciFuncPrincipal, setupTarg)
		tc.Close()
		wg.Done()
	}()

	err := StartDelegateInstance(pc, []Intent{ir1.Data.Intent, ir2.Data.Intent, ir3.Data.Intent})
	assert.NilError(t, err)
	pc.Close()

	wg.Wait()
	assert.DeepEqual(t, correctApprovals, approved)
}
