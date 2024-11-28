package authgrants

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
)

// Delegate client: a hop client that descends from a Delegate proxy server
//  session with a Principal client. Requests an authorization grant from the
//  principal to connect to some Target server and perform some action(s).
//
//  Responsibilities [status]:
//  - connect to Delegate proxy server unix socket
//  - create and send Intent Requests

type delegateInstance struct {
	principalConn  net.Conn
	intentRequests []Intent
}

// StartDelegateInstance sends all intent requests to the principal. Caller
// responsible for closing pc when done with it.
func StartDelegateInstance(pc net.Conn, irs []Intent) error {
	if pc == nil {
		return fmt.Errorf("delegate: must provide non-nil connection to principal")
	}
	if len(irs) == 0 {
		return fmt.Errorf("delegate: must provide at least one intent request")
	}

	di := delegateInstance{
		principalConn:  pc,
		intentRequests: irs,
	}

	return di.sendIntentRequests()
}

func (d *delegateInstance) sendIntentRequests() error {
	if d.principalConn == nil {
		return fmt.Errorf("delegate: not connected to principal")
	}

	oneApproved := false
	for _, ir := range d.intentRequests {
		err := WriteIntentRequest(d.principalConn, ir)
		if err != nil {
			logrus.Error("delegate: error sending intent request")
			continue
		}
		resp, err := ReadConfOrDenial(d.principalConn)
		if err != nil {
			logrus.Error("delegate: error reading intent conf or denial")
			continue
		}
		if resp.MsgType == IntentConfirmation {
			logrus.Info("delegate: intent request confirmed")
			oneApproved = true
		} else {
			logrus.Infof("delegate: intent request denied with reason: %s", resp.Data.Denial)
		}
	}
	logrus.Info("delegate: done sending intent requests")
	if oneApproved {
		return nil
	}
	// TODO here block
	return fmt.Errorf("delegate: no intent requests confirmed")

}
