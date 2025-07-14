package hopclient

import (
	"fmt"
	"net"
	"sync"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/common"
	"hop.computer/hop/core"
	"hop.computer/hop/flags"
	"hop.computer/hop/transport"
	"hop.computer/hop/tubes"

	"github.com/sirupsen/logrus"
)

type principalSubclient struct {
	client         *HopClient
	unrelProxyTube *tubes.Unreliable
}

//  Principal client: a hop client that is authorized on both the Delegate
//   Proxy server and the Target server and can issue authgrants to
//   Delegate clients to perform actions on the Target server.

//   Responsibilities [status]:
//   - receive Intent Requests from Delegate clients [implemented]
//   - approve/deny Intent Requests [implemented]
//   - communicate Intent to Target server [implemented]

// SetCheckIntentCallback can be used to set a custom approver for intent requests
func (c *HopClient) SetCheckIntentCallback(f authgrants.CheckIntentCallback) error {
	if c.hostconfig == nil {
		return fmt.Errorf("can't set check intent callback without config loaded")
	}
	if !c.hostconfig.IsPrincipal {
		return fmt.Errorf("can't set check intent callback for client with IsPrincipal not set")
	}
	c.checkIntentLock.Lock()
	c.checkIntent = f
	c.checkIntentLock.Unlock()
	return nil
}

// allows principal client to keep track of unreliable principal proxy
// tubes before the reliable has received the tube id
type ptProxyTubeQueue struct {
	// +checklocks:lock
	tubes map[byte]*tubes.Unreliable
	lock  *sync.Mutex
	cv    sync.Cond
}

// newPTProxyTubeQueue creates a synchronized set of unreliable principal proxy tubes
func newPTProxyTubeQueue() *ptProxyTubeQueue {
	proxyLock := sync.Mutex{}
	proxyQueue := &ptProxyTubeQueue{
		tubes: make(map[byte]*tubes.Unreliable), // tube ID --> tube
		lock:  &proxyLock,
		cv:    *sync.NewCond(&proxyLock),
	}
	return proxyQueue
}

func (c *HopClient) newPrincipalInstanceSetup(delTube *tubes.Reliable, pq *ptProxyTubeQueue) {
	ci := func(intent authgrants.Intent, cert *certs.Certificate) error {
		c.checkIntentLock.Lock()
		defer c.checkIntentLock.Unlock()
		if c.ExecTube != nil {
			c.ExecTube.SuspendPipes()
		}
		err := c.checkIntent(intent, cert)
		if c.ExecTube != nil {
			c.ExecTube.ResumePipes()
		}
		return err
	}

	var psubclient *principalSubclient
	var err error

	// read unreliable tube id
	tubeID, err := authgrants.ReadUnreliableProxyID(delTube)
	if err != nil {
		logrus.Error("principal: error reading unreliable tube id")
		delTube.Close()
		return
	}

	// check (and keep checking on signal) for the unreliable tube with the id
	pq.lock.Lock()
	logrus.Info("principal: acquired pq.lock for the first time")
	for _, ok := pq.tubes[tubeID]; ok; {
		logrus.Info("tube not here yet. waiting...")
		pq.cv.Wait()
	}

	proxyTube := pq.tubes[tubeID]

	logrus.Info("principal: got the unreliable tube")
	delete(pq.tubes, tubeID)
	pq.lock.Unlock()

	setup := func(url core.URL, verifyCallback authgrants.AdditionalVerifyCallback) (net.Conn, error) {
		psubclient, err = c.setupTargetClient(url, proxyTube, verifyCallback)
		if err != nil {
			logrus.Error("eror setting up target client")
			return nil, err
		}
		logrus.Info("principal: setup successful for psubclient")
		return psubclient.client.newAuthgrantTube()
	}

	logrus.Info("starting principal instance")

	authgrants.StartPrincipalInstance(delTube, ci, setup)
	delTube.Close()

	if psubclient != nil {
		logrus.Info("principal: closing subclient with target.")
		if psubclient.client != nil {
			psubclient.client.Close()
		}
		// stop proxying
		if psubclient.unrelProxyTube != nil {
			psubclient.unrelProxyTube.Close()
		}
	} else {
		logrus.Info("principal: psubclient is nil")
	}
}

func (c *HopClient) setupTargetClient(targURL core.URL, dt *tubes.Unreliable, verifyCallback authgrants.AdditionalVerifyCallback) (*principalSubclient, error) {
	psubclient := &principalSubclient{
		unrelProxyTube: dt,
	}

	// load client config from default path
	cflags := &flags.ClientFlags{
		ConfigPath: c.RawConfigFilePath,
		Address:    &targURL,
		Headless:   true,
		UsePty:     false,
	}
	hc, err := flags.LoadClientConfigFromFlags(cflags)
	if err != nil {
		return nil, err
	}

	client, err := NewHopClient(hc)
	if err != nil {
		return psubclient, err
	}

	// TODO(hosono) this satisfies checklocks, but it feels like hack
	c.checkIntentLock.Lock()
	intent := c.checkIntent
	c.checkIntentLock.Unlock()

	err = client.SetCheckIntentCallback(intent)
	if err != nil {
		return psubclient, err
	}
	client.RawConfigFilePath = c.RawConfigFilePath
	psubclient.client = client
	err = client.authenticatorSetup()
	if err != nil {
		return nil, err
	}

	transportConfig := transport.ClientConfig{
		Exchanger: client.authenticator,
		Verify:    client.authenticator.GetVerifyConfig(),
		Leaf:      client.authenticator.GetLeaf(),
		ServerKey: client.authenticator.GetServerKey(),
	}

	transportConfig.Verify.AddVerifyCallback = transport.AdditionalVerifyCallback(verifyCallback)

	client.TransportConn, err = transport.DialNP(client.hostconfig.HostURL().Address(), dt, transportConfig)
	if err != nil {
		return psubclient, err
	}
	// defer close?
	err = client.TransportConn.Handshake()
	if err != nil {
		return psubclient, err
	}

	config := tubes.Config{
		Timeout: client.hostconfig.DataTimeout,
		Log:     logrus.WithField("muxer", "principal subclient"),
	}
	client.TubeMuxer = tubes.Client(client.TransportConn, &config)
	err = client.userAuthorization()
	if err != nil {
		return nil, err
	}
	client.connected = true

	go client.HandleTubes()

	return psubclient, nil
}

func (c *HopClient) newAuthgrantTube() (*tubes.Reliable, error) {
	return c.TubeMuxer.CreateReliableTube(common.AuthGrantTube)
}
