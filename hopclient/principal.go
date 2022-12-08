package hopclient

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/common"
	"hop.computer/hop/flags"
	"hop.computer/hop/transport"
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

	targetConn, err := c.setUpDelegateProxyToTarget(i)
	if err != nil {
		return false, err
	}

	// establish hop session with target
	targetClient, err := setupTargetClient(targetConn, i)
	if err != nil {
		return false, err
	}
	defer targetClient.Close()

	// start authgrant tube
	agt, err := targetClient.newAuthgrantTube()
	if err != nil {
		return false, err
	}

	// send intent communication
	err = authgrants.SendIntentCommunication(agt, i)
	if err != nil {
		return false, err
	}

	// await response from target
	resp, err := authgrants.ReadConfOrDenial(agt)
	if err != nil {
		return false, err
	}
	if resp.MsgType == authgrants.IntentDenied {
		return false, fmt.Errorf(resp.Data.Denial)
	}

	return true, nil
}

func setupTargetClient(targetConn *tubes.Unreliable, i authgrants.Intent) (*HopClient, error) {

	// TODO(baumanl): think through best way to get the config for this
	// load client config from default path
	cflags := &flags.ClientFlags{
		ConfigPath: "", // TODO(baumanl): keep track of the path used when the principal itself started?
		Address:    i.TargetURL(),
		Headless:   true,
		UsePty:     false,
	}
	hc, err := flags.LoadClientConfigFromFlags(cflags)
	if err != nil {
		return nil, err
	}

	client, err := NewHopClient(hc)
	if err != nil {
		return nil, err
	}

	// TODO(baumanl): necessary to do all of authenticator setup again?
	// or could c.authenticator (principal's authenticator) sometimes be used
	// instead?
	err = client.authenticatorSetup(nil)
	if err != nil {
		return nil, err
	}

	transportConfig := transport.ClientConfig{
		Exchanger: client.authenticator,
		Verify:    client.authenticator.GetVerifyConfig(),
		Leaf:      client.authenticator.GetLeaf(),
	}

	client.TransportConn, err = transport.DialNP(client.hostconfig.HostURL().Address(), targetConn, transportConfig)
	if err != nil {
		return nil, err
	}
	// defer close?
	err = client.TransportConn.Handshake()
	if err != nil {
		return nil, err
	}

	client.TubeMuxer = tubes.NewMuxer(client.TransportConn, client.TransportConn, client.hostconfig.DataTimeout, nil)
	err = client.userAuthorization()
	if err != nil {
		return nil, err
	}
	client.connected = true

	return client, nil
}

func (c *HopClient) setUpDelegateProxyToTarget(i authgrants.Intent) (*tubes.Unreliable, error) {

	// open reliable principal proxy tube with delegate proxy
	delegateProxyConn, err := c.newReliablePrincipalProxyTube()
	if err != nil {
		return nil, err
	}
	defer delegateProxyConn.Close()

	// send TargetInfo to delegate proxy
	err = authgrants.WriteTargetInfo(i, delegateProxyConn)
	if err != nil {
		return nil, err
	}

	// read response (whether delegate proxy successfully connected to target)
	err = authgrants.ReadResponse(delegateProxyConn)
	if err != nil {
		return nil, err
	}

	// open unreliable tube with delegate proxy
	unreliableDelProxyConn, err := c.newUnreliablePrincipalProxyTube()
	if err != nil {
		return nil, err
	}

	// send tubeID
	err = authgrants.WriteUnreliableProxyID(delegateProxyConn, unreliableDelProxyConn.GetID())
	if err != nil {
		return nil, err
	}

	// await confirmation that delegate proxy ready to proxy with unreliable tube
	err = authgrants.ReadResponse(delegateProxyConn)
	if err != nil {
		return nil, err
	}
	return unreliableDelProxyConn, nil
}

func (c *HopClient) newReliablePrincipalProxyTube() (*tubes.Reliable, error) {
	return c.TubeMuxer.CreateReliableTube(common.PrincipalProxyTube)
}

func (c *HopClient) newUnreliablePrincipalProxyTube() (*tubes.Unreliable, error) {
	return c.TubeMuxer.CreateUnreliableTube(common.PrincipalProxyTube)
}

func (c *HopClient) newAuthgrantTube() (*tubes.Reliable, error) {
	return c.TubeMuxer.CreateReliableTube(common.AuthGrantTube)
}
