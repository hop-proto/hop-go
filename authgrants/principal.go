package authgrants

import (
	"fmt"
	"io"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/core"
)

// PrincipalInstance used to manage intent requests from a delegate to a single target
type PrincipalInstance struct {
	DelegateConn    io.ReadWriter
	TargetConn      io.ReadWriter
	TargetInfo      core.URL
	TargetConnected bool

	CheckIntent     func(Intent) error
	SetUpTargetConn func(core.URL) (io.ReadWriter, error)
}

// Run reads intent requests from the DelegateConn until it closes
func (p *PrincipalInstance) Run() {
	for {
		err := p.HandleIntentRequest()
		if err != nil {
			logrus.Errorf("error handling intent request. Quitting.")
			return
		}
	}
}

// HandleIntentRequest performs both principal and target checks. sends intent denied or confirmed to delegate.
func (p *PrincipalInstance) HandleIntentRequest() error {
	i, err := ReadIntentRequest(p.DelegateConn)
	if err != nil {
		logrus.Errorf("principal: error reading ir: %s", err)
		return err
	}
	err = p.doIntentRequestChecks(i)
	if err != nil {
		SendIntentDenied(p.DelegateConn, err.Error())
		return err
	}
	return nil
}

// if err == nil --> confirm; if err != nil --> deny
func (p *PrincipalInstance) doIntentRequestChecks(i Intent) error {
	targURL := i.TargetURL()
	if p.TargetConnected && p.TargetInfo != targURL {
		return fmt.Errorf("received intent request for different target")
	}

	err := p.CheckIntent(i)
	if err != nil {
		return err
	}

	if !p.TargetConnected {
		tc, err := p.SetUpTargetConn(targURL)
		if err != nil {
			return fmt.Errorf("target setup failed: %s", err)
		}
		p.TargetConn = tc
		p.TargetInfo = targURL
		p.TargetConnected = true
	}

	err = SendIntentCommunication(p.TargetConn, i)
	if err != nil {
		return fmt.Errorf("error sending intent comm: %s", err)
	}

	resp, err := ReadConfOrDenial(p.TargetConn)
	if err != nil {
		return fmt.Errorf("error reading target response: %s", err)
	}
	if resp.MsgType == IntentDenied {
		return SendIntentDenied(p.DelegateConn, resp.Data.Denial)
	}

	return SendIntentConfirmation(p.DelegateConn)
}
