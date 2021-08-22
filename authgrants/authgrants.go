//Package authgrants provides support for the authorization grant protocol.
package authgrants

import (
	"errors"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/keys"
	"zmap.io/portal/tubes"
)

type AuthGrantConn struct {
	conn net.Conn
}

func NewAuthGrantConnFromMux(m *tubes.Muxer) (*AuthGrantConn, error) {
	t, e := m.CreateTube(tubes.AuthGrantTube)
	if e != nil {
		return nil, e
	}
	return &AuthGrantConn{conn: t}, nil
}

func NewAuthGrantConn(c net.Conn) *AuthGrantConn {
	return &AuthGrantConn{conn: c}
}

func (c *AuthGrantConn) Close() error {
	return c.conn.Close()
}

//GetAuthGrant is used by the Client to get an authorization grant from its Principal
func (c *AuthGrantConn) GetAuthGrant(digest [sha3Len]byte, sUser string, hostname string, port string, shell bool, cmd string) (int64, error) {
	e := c.sendIntentRequest(digest, sUser, hostname, port, shell, cmd)
	if e != nil {
		logrus.Fatal("C: error sending intent request: ", e)
	}
	logrus.Infof("C: WROTE INTENT TO UDS")
	resptype, response, err := c.ReadResponse()
	if err != nil {
		logrus.Fatalf("S: ERROR GETTING RESPONSE: %v", err)
	}
	//TODO(baumanl): SET TIMEOUT STUFF + BETTER ERROR CHECKING
	switch resptype {
	case IntentConfirmation:
		return fromIntentConfirmationBytes(response[TypeLen:]).deadline, nil
	case IntentDenied:
		reason := fromIntentDeniedBytes(response[TypeLen:]).reason
		logrus.Infof("Reason for denial: %v", reason)
		return 0, errors.New("principal denied Intent Request with reason: " + reason)
	default:
		return 0, errors.New("received message with unknown message type")
	}
}

//HandleIntentComm is used by a Server to handle an INTENT_COMMUNICATION from a Principal
func (c *AuthGrantConn) HandleIntentComm() (keys.PublicKey, time.Time, string, string, error) {
	msg, e := c.readIntentCommunication()
	if e != nil {
		logrus.Fatalf("error reading intent communication")
	}
	intent := fromIntentCommunicationBytes(msg)
	logrus.Infof("Pretending s2 approved intent request") //TODO(baumanl): check policy or something?
	k := keys.PublicKey(intent.sha3)
	t := time.Now().Add(time.Minute)
	user := intent.serverUsername
	action := intent.action
	return k, t, user, action, nil
}

//ReadResponse gets either an intent confirmation or intent denied message
func (c *AuthGrantConn) ReadResponse() (byte, []byte, error) {
	responseType := make([]byte, 1)
	_, err := c.conn.Read(responseType)
	if err != nil {
		return responseType[0], nil, err
	}
	logrus.Infof("Got response type: %v", responseType)
	//TODO(baumanl): SET TIMEOUT STUFF + BETTER ERROR CHECKING
	switch responseType[0] {
	case IntentConfirmation:
		b, e := c.readIntentConf()
		return IntentConfirmation, b, e
	case IntentDenied:
		b, e := c.readIntentDenied()
		return IntentDenied, b, e
	default:
		return responseType[0], nil, errors.New("bad msg type")
	}
}
