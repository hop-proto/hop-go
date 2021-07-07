package authgrants

import (
	"errors"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
)

/*Used by Client Process to get an authorization grant from its Principal*/
func GetAuthGrant(digest [SHA3_LEN]byte, sUser string, addr string, cmd []string) (int64, error) {
	intent := NewIntentRequest(digest, sUser, addr, cmd)
	c, err := net.Dial("unix", "echo1.sock") //TODO: address of UDS
	if err != nil {
		logrus.Fatal(err)
	}
	defer c.Close()
	logrus.Infof("C: CONNECTED TO UDS: [%v]", c.RemoteAddr().String())
	c.Write(intent.ToBytes())

	responseType := make([]byte, 1)
	_, err = c.Read(responseType)
	if err != nil {
		logrus.Fatal(err)
	}

	//TODO: SET TIMEOUT STUFF + BETTER ERROR CHECKING
	if responseType[0] == INTENT_CONFIRMATION {
		conf := make([]byte, INTENT_CONF_SIZE)
		_, err := c.Read(conf)
		if err != nil {
			return 0, err
		}
		return FromIntentConfirmationBytes(conf).Deadline, nil
	} else if responseType[0] == INTENT_DENIED {
		reason_length := make([]byte, 1)
		_, err := c.Read(reason_length)
		if err != nil {
			return 0, err
		}
		reason := make([]byte, int(reason_length[0]))
		_, err = c.Read(reason)
		if err != nil {
			return 0, err
		}
		//logrus.Printf("Reason for denial: %v", FromIntentDeniedBytes(reason).reason)
		return 0, errors.New("principal denied Intent Request")
	}
	return 0, errors.New("received message with unknown message type")
}

func (r *IntentRequest) Display() {
	fmt.Printf("Allow %v@%v to run %v on %v@%v? \nEnter yes or no: ",
		r.clientUsername,
		r.clientSNI,
		r.action,
		r.serverSNI,
		r.serverUsername)
}
