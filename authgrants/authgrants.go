//Package authgrants provides support for the authorization grant protocol.
package authgrants

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/keys"
	"zmap.io/portal/tubes"
)

//AuthGrantConn wraps a net.Conn (either tube or UDS conn) for authorization grant protocol messages
type AuthGrantConn struct {
	conn net.Conn
}

//NewAuthGrantConnFromMux starts a new Tube using provided muxer and uses it for an AuthGrantConn
func NewAuthGrantConnFromMux(m *tubes.Muxer) (*AuthGrantConn, error) {
	t, e := m.CreateTube(tubes.AuthGrantTube)
	if e != nil {
		return nil, e
	}
	return &AuthGrantConn{conn: t}, nil
}

//NewAuthGrantConn returns a new AuthGrantConn using c
func NewAuthGrantConn(c net.Conn) *AuthGrantConn {
	return &AuthGrantConn{conn: c}
}

//Close calls close on underlying conn
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
		fmt.Println("Intent Request Denied with reason: ", reason)
		return 0, ErrIntentDenied
	default:
		return 0, ErrUnknownMessage
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
	var action string
	if intent.grantType == execGrant {
		eg := fromExecGrantBytes(intent.associatedData)
		action = eg.action
	}
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

//Prompt prints the authgrant approval prompt to terminal and continues prompting until user enters "y" or "n"
func (r *Intent) Prompt(reader *io.PipeReader) bool {
	var ans string
	for ans != "y" && ans != "n" {
		if r.grantType == execGrant {
			eg := fromExecGrantBytes(r.associatedData)
			if eg.actionType == commandTube {
				fmt.Printf("\nAllow %v@%v to run %v on %v@%v? [y/n]: ",
					r.clientUsername,
					r.clientSNI,
					eg.action,
					r.serverUsername,
					r.serverSNI)
			} else {
				fmt.Printf("\nAllow %v@%v to open a default shell as %v@%v? [y/n]: ",
					r.clientUsername,
					r.clientSNI,
					r.serverUsername,
					r.serverSNI,
				)
			}
		}

		scanner := bufio.NewScanner(reader)
		scanner.Scan()
		ans = scanner.Text()
	}
	return ans == "y"
}
