//Package authgrants provides support for the authorization grant protocol.
package authgrants

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	t, e := m.CreateTube(byte(2))
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
func (c *AuthGrantConn) GetAuthGrant(digest [sha3Len]byte, sUser string, hostname string, port string, grantType byte, arg string) (int64, error) {
	e := c.sendIntentRequest(digest, sUser, hostname, port, grantType, arg)
	if e != nil {
		logrus.Error("C: error sending intent request: ", e)
		return 0, e
	}
	logrus.Infof("C: WROTE INTENT TO UDS")
	resptype, response, err := c.ReadResponse()
	if err != nil {
		logrus.Errorf("S: ERROR GETTING RESPONSE: %v", err)
		return 0, err
	}
	//TODO(baumanl): SET TIMEOUT STUFF + BETTER ERROR CHECKING
	switch resptype {
	case IntentConfirmation:
		return fromIntentConfirmationBytes(response[dataOffset:]).deadline, nil
	case IntentDenied:
		reason := fromIntentDeniedBytes(response[dataOffset:]).reason
		fmt.Println("Intent Request Denied with reason: ", reason)
		return 0, ErrIntentDenied
	default:
		return 0, ErrUnknownMessage
	}
}

//HandleIntentComm is used by a Server to handle an INTENT_COMMUNICATION from a Principal
func (c *AuthGrantConn) HandleIntentComm() (keys.PublicKey, time.Time, string, string, byte, error) {
	msg, e := c.readIntentCommunication()
	if e != nil {
		logrus.Error("error reading intent communication")
		return keys.PublicKey{}, time.Now(), "", "", 0, e
	}
	intent := fromIntentCommunicationBytes(msg)
	logrus.Infof("Pretending s2 approved intent request") //TODO(baumanl): check policy or something?
	k := keys.PublicKey(intent.sha3)
	t := time.Now().Add(authGrantValidTime)
	return k, t, intent.serverUsername, intent.associatedData, intent.actionType, nil
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

func (c *AuthGrantConn) readIntent(msgType byte) ([]byte, error) {
	t := make([]byte, 1)
	_, err := c.conn.Read(t)
	if err != nil {
		return nil, err
	}
	if t[0] == msgType {
		irh := make([]byte, irHeaderLen)
		_, err = c.conn.Read(irh)
		if err != nil {
			return nil, err
		}
		len := binary.BigEndian.Uint16(irh[associatedDataLenOffset:])
		data := make([]byte, len)
		_, err = c.conn.Read(data)
		if err != nil {
			return nil, err
		}
		return append(t, append(irh, data...)...), nil

	}
	return nil, errors.New("bad msg type")
}

//ReadIntentDenied gets the reason for denial
func (c *AuthGrantConn) readIntentDenied() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = IntentDenied
	_, err := c.conn.Read(buf[1:])
	if err != nil {
		return nil, err
	}
	buf = append(buf, make([]byte, int(buf[1]))...)
	_, err = c.conn.Read(buf[2:])
	if err != nil {
		return nil, err
	}
	return buf, nil
}

//ReadIntentConf
func (c *AuthGrantConn) readIntentConf() ([]byte, error) {
	buf := make([]byte, deadlineLen+1)
	buf[0] = IntentConfirmation
	_, err := c.conn.Read(buf[1:])
	return buf, err
}

//ReadIntentRequest gets Intent Request bytes
func (c *AuthGrantConn) ReadIntentRequest() ([]byte, error) {
	return c.readIntent(IntentRequest)
}

func (c *AuthGrantConn) readIntentCommunication() ([]byte, error) {
	return c.readIntent(IntentCommunication)
}

//SendIntentDenied writes an intent denied message to provided tube
func (c *AuthGrantConn) SendIntentDenied(reason string) error {
	_, err := c.conn.Write(newIntentDenied(reason).toBytes())
	return err
}

//SendIntentConf writes an intent conf message to provided tube
func (c *AuthGrantConn) SendIntentConf(t time.Time) error {
	_, err := c.conn.Write(newIntentConfirmation(t).toBytes())
	return err
}

//SendIntentRequest writes an intent request msg
func (c *AuthGrantConn) sendIntentRequest(digest [sha3Len]byte, sUser string, hostname string, port string, grantType byte, cmd string) error {
	_, err := c.conn.Write(newIntentRequest(digest, sUser, hostname, port, grantType, cmd).toBytes())
	return err
}

//SendIntentCommunication writes an intent communication msg
func (c *AuthGrantConn) SendIntentCommunication(intentData *Intent) error {
	_, err := c.conn.Write(commFromReq(intentData.toBytes()))
	return err
}

//WriteRawBytes writes bytes to underlying conn without regard for msg type
func (c *AuthGrantConn) WriteRawBytes(data []byte) error {
	_, err := c.conn.Write(data)
	return err
}

//GetIntentRequest reads IntentRequest bytes and parses them into an Intent object
func (c *AuthGrantConn) GetIntentRequest() (*Intent, error) {
	intentBytes, err := c.ReadIntentRequest()
	if err != nil {
		return nil, err
	}
	return fromIntentRequestBytes(intentBytes), nil
}
