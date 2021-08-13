//Package authgrants provides support for the authorization grant protocol.
package authgrants

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/channels"
	"zmap.io/portal/codex"
	"zmap.io/portal/keys"
	"zmap.io/portal/npc"
	"zmap.io/portal/transport"
	"zmap.io/portal/userauth"
)

//GetAuthGrant is used by the Client to get an authorization grant from its Principal
func GetAuthGrant(digest [sha3Len]byte, sUser string, addr string, cmd string) (int64, error) {
	intent := newIntentRequest(digest, sUser, addr, cmd)
	sock := "@auth"                  //TODO(baumanl): make generalizeable
	c, err := net.Dial("unix", sock) //TODO(baumanl): address of UDS (probably switch to abstract location)
	if err != nil {
		logrus.Fatal(err)
	}
	defer c.Close()

	logrus.Infof("C: CONNECTED TO UDS: [%v]", c.RemoteAddr().String())
	_, e := c.Write(intent.toBytes())
	if e != nil {
		logrus.Fatal("C: error writing to UDS")
	}
	logrus.Infof("C: WROTE INTENT TO UDS")
	response, resptype, err := GetResponse(c)
	if err != nil {
		logrus.Fatalf("S: ERROR GETTING RESPONSE: %v", err)
	}

	//TODO(baumanl): SET TIMEOUT STUFF + BETTER ERROR CHECKING
	switch resptype {
	case IntentConfirmation:
		return fromIntentConfirmationBytes(response[TypeLen:]).Deadline, nil
	case IntentDenied:
		reason := fromIntentDeniedBytes(response[TypeLen:]).reason
		logrus.Infof("Reason for denial: %v", reason)
		return 0, errors.New("principal denied Intent Request")
	default:
		return 0, errors.New("received message with unknown message type")
	}
}

//Principal is used by the Principal to respond to INTENT_REQUESTS from a Client
func Principal(agc *channels.Reliable, m *channels.Muxer, execCh *codex.ExecChan, config *transport.ClientConfig) {
	defer func() {
		agc.Close()
		logrus.Info("Closed AGC")
	}()
	logrus.SetOutput(io.Discard)
	execCh.Restore()
	intent, err := ReadIntentRequest(agc)
	if err != nil {
		logrus.Fatalf("ERROR READING INTENT REQUEST: %v", err)
	}

	logrus.Info("C: PRINCIPAL REC: INTENT_REQUEST")
	req := fromIntentRequestBytes(intent[TypeLen:])

	execCh.Restore()
	logrus.SetOutput(os.Stdout)
	r := execCh.Redirect()

	allow := req.prompt(r)

	execCh.Raw()
	execCh.Resume()
	logrus.SetOutput(io.Discard)
	if allow {
		logrus.Info("C: USER CONFIRMED INTENT_REQUEST. CONTACTING S2...")

		//create npc with server
		npcCh, e := m.CreateChannel(channels.NpcChannel) //How do I close this on the principal side?
		logrus.Info("started NPC from principal")
		if e != nil {
			logrus.Fatal("C: Error starting NPC")
		}

		addr := req.serverSNI + ":" + strconv.Itoa(int(req.port))
		e = npc.Start(npcCh, addr)
		if e != nil {
			logrus.Fatal("Issue proxying connection")
		}

		//start hop session over NPC
		tclient, e := transport.DialNPC("npc", addr, npcCh, config)
		if e != nil {
			logrus.Fatal("error dialing npc")
		}
		e = tclient.Handshake()
		if e != nil {
			logrus.Fatal("Handshake failed: ", e)
		}
		logrus.Info("handshake successful")
		npcMuxer := channels.NewMuxer(tclient, tclient)
		go npcMuxer.Start()

		uaCh, _ := npcMuxer.CreateChannel(channels.UserAuthChannel)
		if ok := userauth.RequestAuthorization(uaCh, config.KeyPair.Public, req.serverUsername); !ok {
			logrus.Fatal("Not authorized.")
		}
		logrus.Info("User authorization complete")

		//start AGC and send INTENT_COMMUNICATION
		npcAgc, e := npcMuxer.CreateChannel(channels.AgcChannel)
		if e != nil {
			logrus.Fatal("Error creating AGC: ", e)
		}
		logrus.Info("CREATED AGC")
		_, e = npcAgc.Write(commFromReq(intent))
		if e != nil {
			logrus.Info("Issue writing intent comm to npcAgc")
		}
		response, _, e := GetResponse(npcAgc)
		logrus.Info("got response")
		if e != nil {
			logrus.Fatalf("C: error reading from agc: %v", e)
		}

		//write response back to server asking for Authorization Grant
		_, err = agc.Write(response)
		if err != nil {
			logrus.Fatalf("C: error writing to agc: %v", err)
		}
		//TODO(baumanl): Add logic to deal with potential IntentDenied from server
		logrus.Infof("C: WROTE IntentConfirmation")
		npcAgc.Close()

		// Want to keep this session open in case the "server 2" wants to continue chaining hop sessions together
		// TODO(baumanl): Simplify this. Should only get authorization grant channels?
		go func() {
			for {
				c, e := npcMuxer.Accept()
				if e != nil {
					logrus.Fatalf("Error accepting channel: %v", e)
				}
				logrus.Infof("Accepted channel of type: %v", c.Type())
				if c.Type() == channels.AgcChannel {
					go Principal(c, npcMuxer, execCh, config)
				} else if c.Type() == channels.NpcChannel {
					//go do something?
					c.Close()
				} else if c.Type() == channels.ExecChannel {
					//go do something else?
					c.Close()
				} else {
					//bad channel
					c.Close()
				}
			}
		}()
	} else {
		agc.Write(newIntentDenied("User denied.").toBytes())
	}
}

//HandleIntentComm is used by a Server to handle an INTENT_COMMUNICATION from a Principal
func HandleIntentComm(agc *channels.Reliable) (keys.PublicKey, time.Time, string, string, error) {
	msg, e := readIntentCommunication(agc)
	if e != nil {
		logrus.Fatalf("error reading intent communication")
	}
	intent := fromIntentCommunicationBytes(msg[TypeLen:])
	logrus.Infof("Pretending s2 approved intent request") //TODO(baumanl): check policy or something?
	k := keys.PublicKey(intent.sha3)
	t := time.Now().Add(time.Minute)
	user := intent.serverUsername
	action := strings.Join(intent.action, " ")
	return k, t, user, action, nil

}

//SendIntentDenied writes an intent denied message to provided channel
func SendIntentDenied(agc *channels.Reliable, reason string) {
	agc.Write(newIntentDenied(reason).toBytes())
}

//SendIntentConf writes and intent conf message to provided channel
func SendIntentConf(agc *channels.Reliable, t time.Time) {
	_, e := agc.Write(newIntentConfirmation(t).toBytes())
	if e != nil {
		logrus.Errorf("Issue writing intent conf")
	}
}

//Display prints the authgrant approval prompt to terminal and continues prompting until user enters "y" or "n"
func (r *intentRequestMsg) prompt(reader *io.PipeReader) bool {
	var ans string
	for ans != "y" && ans != "n" {
		fmt.Printf("\nAllow %v@%v to run %v on %v@%v? [y/n]: ",
			r.clientUsername,
			r.clientSNI,
			r.action,
			r.serverUsername,
			r.serverSNI)
		scanner := bufio.NewScanner(reader)
		scanner.Scan()
		ans = scanner.Text()
	}
	return ans == "y"

}
