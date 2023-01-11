package authgrants

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/core"
)

type checkIntentFunc func(Intent) error
type setUpTargetConnFunc func(core.URL) (net.Conn, error)

// PrincipalInstance used to manage intent requests from a delegate to a single target
type principalInstance struct {
	delegateConn    net.Conn
	targetConn      net.Conn
	targetInfo      core.URL
	targetConnected bool

	checkIntent     checkIntentFunc
	setUpTargetConn setUpTargetConnFunc
}

// StartPrincipalInstance creates and runs a new principal instance. errors if su is nil.
func StartPrincipalInstance(dc net.Conn, ci checkIntentFunc, su setUpTargetConnFunc) error {
	if su == nil {
		return fmt.Errorf("principal: must provide non-nil set up target function")
	}

	pi := principalInstance{
		delegateConn:    dc,
		checkIntent:     ci,
		setUpTargetConn: su,
	}
	defer func() {
		pi.delegateConn.Close()
		if pi.targetConnected {
			pi.targetConn.Close()
		}
	}()

	if ci == nil {
		pi.checkIntent = defaultRejectAll
	}

	pi.run()
	return nil
}

func defaultRejectAll(i Intent) error {
	return fmt.Errorf("default checkIntent func rejects all intent requests")
}

// Run reads intent requests from the DelegateConn until it closes or error
// reading intent request or sending conf/denial message to delegate
func (p *principalInstance) run() {
	// TODO(baumanl): add way to close without waiting for delegateconn to close?
	for {
		err := p.handleIntentRequest()
		if err != nil {
			logrus.Errorf("principal: error handling intent request. Quitting.")
			return
		}
	}
}

// HandleIntentRequest performs both principal and target checks. sends intent denied or confirmed to delegate.
func (p *principalInstance) handleIntentRequest() error {
	i, err := ReadIntentRequest(p.delegateConn)
	if err != nil {
		logrus.Errorf("principal: error reading ir: %s", err)
		return err
	}
	return p.doIntentRequestChecks(i)
}

// returns error if issue sending conf or denial
func (p *principalInstance) doIntentRequestChecks(i Intent) error {
	targURL := i.TargetURL()
	if p.targetConnected && p.targetInfo != targURL {
		return WriteIntentDenied(p.delegateConn, "principal: received intent request for different target")
	}

	err := p.checkIntent(i)
	if err != nil {
		return WriteIntentDenied(p.delegateConn, err.Error())
	}

	if !p.targetConnected {
		tc, err := p.setUpTargetConn(targURL)
		if err != nil {
			return WriteIntentDenied(p.delegateConn, fmt.Sprintf("principal: target setup failed: %s", err))
		}
		p.targetConn = tc
		p.targetInfo = targURL
		p.targetConnected = true
	}

	err = WriteIntentCommunication(p.targetConn, i)
	if err != nil {
		return WriteIntentDenied(p.delegateConn, fmt.Sprintf("principal: error sending intent comm: %s", err))
	}

	resp, err := ReadConfOrDenial(p.targetConn)
	if err != nil {
		return WriteIntentDenied(p.delegateConn, fmt.Sprintf("principal: error reading target response: %s", err))
	}
	if resp.MsgType == IntentDenied {
		return WriteIntentDenied(p.delegateConn, resp.Data.Denial)
	}
	return WriteIntentConfirmation(p.delegateConn)
}
