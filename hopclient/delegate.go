package hopclient

import (
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
	"hop.computer/hop/common"
	"hop.computer/hop/core"
	"hop.computer/hop/keys"
	"hop.computer/hop/transport"
)

//  Delegate client: a hop client that descends from a Delegate proxy server
//   session with a Principal client. Requests an authorization grant from the
//   principal to connect to some Target server and perform some action(s).

//   Responsibilities [status]:
//   - connect to Delegate proxy server unix socket [TODO]
//   - create and send Intent Requests [TODO]

func makeAuthenticatorWithGeneratedKeypair(targetURL core.URL) core.Authenticator {
	keypair := keys.GenerateNewX25519KeyPair()
	leaf := loadLeaf("", true, &keypair.Public, targetURL)
	return core.InMemoryAuthenticator{
		X25519KeyPair: keypair,
		VerifyConfig: transport.VerifyConfig{
			InsecureSkipVerify: true, // TODO(dadrian): Host-key verification
		},
		Leaf: leaf,
	}
}

func (c *HopClient) getAuthorization() error {
	// make authenticator
	c.authenticator = makeAuthenticatorWithGeneratedKeypair(c.hostconfig.HostURL())
	// make intent requests
	irs := []authgrants.Intent{}
	irTemplate := authgrants.Intent{
		TargetPort: uint16(c.hostconfig.Port),
		StartTime:  time.Now(),
		ExpTime:    time.Now().Add(time.Minute), // TODO(baumanl): add way to customize this
		TargetSNI: certs.Name{
			Type:  certs.TypeRaw,
			Label: []byte(c.hostconfig.Hostname),
		},
		TargetUsername: c.hostconfig.User,
		DelegateCert:   *c.authenticator.GetLeaf(),
	}
	// need shell authgrant?
	if !c.hostconfig.Headless && c.hostconfig.Cmd == "" {
		irShell := irTemplate
		irShell.GrantType = authgrants.Shell
		irs = append(irs, irShell)
	} else if c.hostconfig.Cmd != "" {
		irCmd := irTemplate
		irCmd.GrantType = authgrants.Command
		irCmd.AssociatedData = authgrants.GrantData{
			CommandGrantData: authgrants.CommandGrantData{
				Cmd: c.hostconfig.Cmd,
			},
		}
		irs = append(irs, irCmd)
	}
	// TODO(baumanl): add other intent request types

	// TODO(baumanl): think more about environment variable/test it
	// connect to delegate proxy --> target
	val, ok := os.LookupEnv("DP_PROXY")
	if !ok {
		val = common.DefaultAgProxyListenSocket // change to default
	}
	pconn, err := net.Dial("unix", val) // TODO(baumanl): config option for
	if err != nil {
		logrus.Errorf("delegate: error dialing ag proxy socket: %s", err)
		return err
	}

	// send targetInfo to the delserver
	err = authgrants.WriteTargetInfo(irTemplate.TargetURL(), pconn)
	if err != nil {
		pconn.Close()
		logrus.Error("delegate: error sending targetInfo to server")
		return err
	}

	c.delServerConn = pconn
	return authgrants.StartDelegateInstance(pconn, irs)
}
