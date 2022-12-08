package hopclient

import (
	"github.com/sirupsen/logrus"
	"hop.computer/hop/authgrants"
	"hop.computer/hop/common"
	"hop.computer/hop/tubes"
)

//  Principal client: a hop client that is authorized on both the Delegate
//   Proxy server and the Target server and can issue authgrants to
//   Delegate clients to perform actions on the Target server.

//   Responsibilities [status]:
//   - receive Intent Requests from Delegate clients [TODO]
//   - approve/deny Intent Requests [TODO]
//   - communicate Intent to Target server [TODO]

// TODO(baumanl): implement Principal hop client

func (c *HopClient) principal(t *tubes.Reliable) {
	// TODO(baumanl): make sure this closes properly if t is closed
	//
	for {
		// TODO(baumanl): add deadlines when implemented on reliable tubes
		err := c.handleIntentRequest(t)
		if err != nil {
			break
		}
	}
}

func (c *HopClient) handleIntentRequest(t *tubes.Reliable) error {
	i, err := authgrants.ReadIntentRequest(t)
	if err != nil {
		logrus.Errorf("principal: error reading intent request: %s", err)
		return err
	}

	// validate intent request
	approved, err := c.checkIntentRequest(i)
	if err != nil || !approved {
		err = authgrants.SendIntentDenied(t, err.Error())
		return err
	}

	// send intent communication to target server
	approved, err = c.checkIntentRequestTarget(i)
	if err != nil || !approved {
		err = authgrants.SendIntentDenied(t, err.Error())
		return err
	}
	return authgrants.SendIntentConfirmation(t)
}

func (c *HopClient) checkIntentRequest(i authgrants.Intent) (bool, error) {
	// TODO(baumanl): make this a customizable callback
	// TODO(baumanl): implement some respectable default options
	logrus.Infof("principal: approving intent request")
	return true, nil // currently approves all intent requests
}

func (c *HopClient) checkIntentRequestTarget(i authgrants.Intent) (bool, error) {
	// open reliable principal proxy tube with delegate proxy
	delegateProxyConn, err := c.newReliablePrincipalProxyTube()
	if err != nil {
		return false, err
	}
	defer delegateProxyConn.Close()

	// send TargetInfo to delegate proxy
	err = authgrants.WriteTargetInfo(i, delegateProxyConn)
	if err != nil {
		return false, err
	}

	// read response (whether delegate proxy successfully connected to target)
	err = authgrants.ReadResponse(delegateProxyConn)
	if err != nil {
		return false, err
	}

	// open unreliable tube with delegate proxy
	unreliableDelProxyConn, err := c.newUnreliablePrincipalProxyTube()
	if err != nil {
		return false, err
	}
	defer unreliableDelProxyConn.Close()

	// send tubeID
	err = authgrants.WriteUnreliableProxyID(delegateProxyConn, unreliableDelProxyConn.GetID())
	if err != nil {
		return false, err
	}

	// await confirmation that delegate proxy ready to proxy with unreliable tube
	err = authgrants.ReadResponse(delegateProxyConn)
	if err != nil {
		return false, err
	}

	// connect to target
	// TODO(baumanl): implement this portion

	return true, nil
}

func (c *HopClient) newReliablePrincipalProxyTube() (*tubes.Reliable, error) {
	return c.TubeMuxer.CreateReliableTube(common.PrincipalProxyTube)
}

func (c *HopClient) newUnreliablePrincipalProxyTube() (*tubes.Unreliable, error) {
	return c.TubeMuxer.CreateUnreliableTube(common.PrincipalProxyTube)
}
