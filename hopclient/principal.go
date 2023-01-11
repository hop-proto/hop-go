package hopclient

import (
	"fmt"
	"net"
	"strconv"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/common"
	"hop.computer/hop/core"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"

	"github.com/sirupsen/logrus"
)

//  Principal client: a hop client that is authorized on both the Delegate
//   Proxy server and the Target server and can issue authgrants to
//   Delegate clients to perform actions on the Target server.

//   Responsibilities [status]:
//   - receive Intent Requests from Delegate clients [implemented]
//   - approve/deny Intent Requests [implemented]
//   - communicate Intent to Target server [implemented]

// SetCheckIntentCallback can be used to set a custom approver for intent requests
func (c *HopClient) SetCheckIntentCallback(f func(authgrants.Intent) error) error {
	if c.hostconfig == nil {
		return fmt.Errorf("can't set check intent callback without config loaded")
	}
	if !c.hostconfig.IsPrincipal {
		return fmt.Errorf("can't set check intent callback for delegate client")
	}
	c.checkIntentLock.Lock()
	c.checkIntent = f
	c.checkIntentLock.Unlock()
	return nil
}

func (c *HopClient) newPrincipalInstanceSetup(delTube *tubes.Reliable) {
	c.checkIntentLock.Lock()
	ci := c.checkIntent
	c.checkIntentLock.Unlock()

	authgrants.StartPrincipalInstance(delTube, ci, c.setupTargetClient)
}

func (c *HopClient) setupTargetClient(targURL core.URL) (net.Conn, error) {
	targetConn, err := c.setUpDelegateProxyToTarget(targURL)
	if err != nil {
		return nil, err
	}

	// TODO(baumanl): think through best way to get the config for this
	// is it too slow to load entire config file again? Better to have
	// that cached?

	hc := c.hostconfig
	hc.Hostname = targURL.Host
	hc.Port, _ = strconv.Atoi(targURL.Port)
	hc.User = targURL.User
	hc.Headless = true
	hc.UsePty = false

	// load client config from default path
	// cflags := &flags.ClientFlags{
	// 	ConfigPath: "", // TODO(baumanl): keep track of the path used when the principal itself started?
	// 	Address:    &targURL,
	// 	Headless:   true,
	// 	UsePty:     false,
	// }
	// hc, err := flags.LoadClientConfigFromFlags(cflags)
	// if err != nil {
	// 	return nil, err
	// }

	client, err := NewHopClient(hc)
	if err != nil {
		return nil, err
	}

	// TODO(baumanl): necessary to do all of authenticator setup again?
	// or could c.authenticator (principal's authenticator) sometimes be used
	// instead?
	// err = client.authenticatorSetup()
	// if err != nil {
	// 	return nil, err
	// }

	// TODO(baumanl): this is temporary. Not generalizable if the principal
	// needs a different authentication method to connect to target than it
	// needed to connect to delegate proxy server
	client.authenticator = c.authenticator

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

	client.TubeMuxer = tubes.NewMuxer(client.TransportConn, client.hostconfig.DataTimeout, false, logrus.WithField("muxer", "principal subclient"))
	go func() {
		err := client.TubeMuxer.Start()
		if err != nil {
			logrus.Error("principal: subclient muxer has stopped with err: ", err)
			return
		}
		logrus.Debug("principal: subclient muxer stopped without error")
	}()
	err = client.userAuthorization()
	if err != nil {
		return nil, err
	}
	client.connected = true

	return client.newAuthgrantTube()
}

func (c *HopClient) setUpDelegateProxyToTarget(targURL core.URL) (*tubes.Unreliable, error) {
	// open reliable principal proxy tube with delegate proxy
	delegateProxyConn, err := c.newReliablePrincipalProxyTube()
	if err != nil {
		return nil, err
	}
	logrus.Info("principal: made a reliable delProxyConn with del proxy")
	defer delegateProxyConn.Close()

	// send TargetInfo to delegate proxy
	err = authgrants.WriteTargetInfo(targURL, delegateProxyConn)
	if err != nil {
		return nil, err
	}
	logrus.Info("principal: wrote target info")

	// read response (whether delegate proxy successfully connected to target)
	err = authgrants.ReadResponse(delegateProxyConn)
	if err != nil {
		logrus.Error("principal: error reading response")
		return nil, err
	}
	logrus.Info("principal: del proxy successfully connected to target!")
	// open unreliable tube with delegate proxy
	unreliableDelProxyConn, err := c.newUnreliablePrincipalProxyTube()
	if err != nil {
		logrus.Error("principal: error starting unreliable proxy tube")
		return nil, err
	}
	logrus.Info("principal: successfully started unreliable proxy tube")

	// send tubeID
	err = authgrants.WriteUnreliableProxyID(delegateProxyConn, unreliableDelProxyConn.GetID())
	if err != nil {
		logrus.Error("principal: error writing unreliable proxy id")
		return nil, err
	}
	logrus.Info("principal: successfully wrote unreliable proxy id")

	// await confirmation that delegate proxy ready to proxy with unreliable tube
	err = authgrants.ReadResponse(delegateProxyConn)
	if err != nil {
		logrus.Error("principal: error reading response from del proxy")
		return nil, err
	}
	logrus.Info("principal: got unreliable proxy conn")
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
