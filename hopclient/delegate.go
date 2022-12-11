package hopclient

import (
	"net"
	"os"
	"time"

	"hop.computer/hop/authgrants"
	"hop.computer/hop/certs"
)

//  Delegate client: a hop client that descends from a Delegate proxy server
//   session with a Principal client. Requests an authorization grant from the
//   principal to connect to some Target server and perform some action(s).

//   Responsibilities [status]:
//   - connect to Delegate proxy server unix socket [TODO]
//   - create and send Intent Requests [TODO]

func (c *HopClient) getAuthorization() error {
	// make authenticator
	c.authenticator = makeAuthenticatorWithGeneratedKeypair(c.hostconfig.HostURL())
	// make intent requests
	irs := []authgrants.Intent{}
	irTemplate := authgrants.Intent{
		TargetPort: uint16(c.hostconfig.Port),
		StartTime:  time.Now(),
		ExpTime:    time.Now().Add(time.Minute),
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

	// connect to delegate proxy --> target
	val, ok := os.LookupEnv("DP_PROXY")
	if !ok {
		val = "default" // change to default
	}
	pconn, err := net.Dial("unix", val) // TODO(baumanl): config option for
	if err != nil {
		return err
	}
	authgrants.StartDelegateInstance(pconn, irs)
	return nil
}
