package authgrants

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/certs"
	"hop.computer/hop/core"
)

// AdditionalVerifyCallback represents a function that is called mid
// handshake. Wraps checkintent.
type AdditionalVerifyCallback func(*certs.Certificate) error

// CheckIntentCallback looks at intent and target cert. error nil if accepted.
type CheckIntentCallback func(Intent, *certs.Certificate) error
type setUpTargetConnCallback func(core.URL, AdditionalVerifyCallback) (net.Conn, error)

// PrincipalInstance used to manage intent requests from a delegate to a single target
type principalInstance struct {
	delegateConn    net.Conn
	targetConn      net.Conn
	targetInfo      core.URL
	targetConnected bool
	targetCert      *certs.Certificate

	checkIntent     CheckIntentCallback
	setUpTargetConn setUpTargetConnCallback
}

// StartPrincipalInstance creates and runs a new principal instance. errors if su is nil. Caller responsible for closing delegateConn
func StartPrincipalInstance(dc net.Conn, ci CheckIntentCallback, su setUpTargetConnCallback) error {
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
		// pi.checkIntent = defaultRejectAll // this is correct
		pi.checkIntent = insecureAcceptAll
	}

	pi.run()
	return nil
}

func defaultRejectAll(i Intent, c *certs.Certificate) error {
	return fmt.Errorf("default checkIntent func rejects all intent requests")
}

func insecureAcceptAll(i Intent, c *certs.Certificate) error {
	logrus.Infof("principal: insecurely accepting intent with no checks")
	return nil
}

// Run reads intent requests from the DelegateConn until it closes or error
// reading intent request or sending conf/denial message to delegate
func (p *principalInstance) run() {
	// TODO(baumanl): add way to close without waiting for delegateconn to close?
	for {
		logrus.Info("principal: waiting for an ir or err")
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
	logrus.Info("principal: read an ir")
	return p.doIntentRequestChecks(i)
}

// returns error if issue sending conf or denial
func (p *principalInstance) doIntentRequestChecks(i Intent) error {
	targURL := i.TargetURL()
	if p.targetConnected && p.targetInfo != targURL {
		return WriteIntentDenied(p.delegateConn, "principal: received intent request for different target")
	}

	if !p.targetConnected {
		logrus.Info("principal: not connected to target")
		checkIntentWithCert := func(cert *certs.Certificate) error {
			p.targetCert = cert
			err := p.checkIntent(i, cert)
			if err != nil {
				WriteIntentDenied(p.delegateConn, err.Error())
			}
			return err
		}
		tc, err := p.setUpTargetConn(targURL, checkIntentWithCert)
		if err != nil {
			logrus.Info("principal: error setting up target connection")
			return WriteIntentDenied(p.delegateConn, fmt.Sprintf("principal: target setup failed: %s", err))
		}
		p.targetConn = tc
		p.targetInfo = targURL
		p.targetConnected = true
		logrus.Info("principal: connected to target")
	} else {
		p.checkIntent(i, p.targetCert)
	}

	err := WriteIntentCommunication(p.targetConn, i)
	if err != nil {
		logrus.Error("principal: error writing intent communication")
		return WriteIntentDenied(p.delegateConn, fmt.Sprintf("principal: error sending intent comm: %s", err))
	}
	logrus.Info("principal: wrote intent communication")

	resp, err := ReadConfOrDenial(p.targetConn)
	if err != nil {
		logrus.Error("principal: error reading conf or denial")
		return WriteIntentDenied(p.delegateConn, fmt.Sprintf("principal: error reading target response: %s", err))
	}

	if resp.MsgType == IntentDenied {
		logrus.Info("principal: read Intent denied")
		return WriteIntentDenied(p.delegateConn, resp.Data.Denial)
	}
	logrus.Info("principal: read Intent Confirmation")
	return WriteIntentConfirmation(p.delegateConn)
}
