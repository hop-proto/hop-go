//Package providing support for the authorization grant protocol.
package authgrants

import (
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
)

/*Used by client to get an authorization grant from its Principal*/
func GetAuthGrant(digest [SHA3_LEN]byte, sUser string, addr string, cmd []string) (int64, error) {
	intent := NewIntentRequest(digest, sUser, addr, cmd)

	sock := "/tmp/auth.sock" //TODO: make generalizeable
	if addr == "127.0.0.1:9999" {
		sock = "/tmp/auth2.sock"
	}

	c, err := net.Dial("unix", sock) //TODO: address of UDS
	if err != nil {
		logrus.Fatal(err)
	}
	defer c.Close()

	logrus.Infof("C: CONNECTED TO UDS: [%v]", c.RemoteAddr().String())
	_, e := c.Write(intent.ToBytes())
	if e != nil {
		logrus.Fatal("C: error writing to UDS")
	}
	logrus.Infof("C: WROTE INTENT TO UDS")
	response, resptype, err := GetResponse(c)
	if err != nil {
		logrus.Fatalf("S: ERROR GETTING RESPONSE: %v", err)
	}

	//TODO: SET TIMEOUT STUFF + BETTER ERROR CHECKING
	switch resptype {
	case INTENT_CONFIRMATION:
		return FromIntentConfirmationBytes(response[TYPE_LEN:]).Deadline, nil
	case INTENT_DENIED:
		reason := FromIntentDeniedBytes(response[TYPE_LEN:]).reason
		logrus.Infof("Reason for denial: %v", reason)
		return 0, errors.New("principal denied Intent Request")
	default:
		return 0, errors.New("received message with unknown message type")
	}

}

/*Go routine for Principal to respond to auth grant requests*/
func Principal(agc *channels.Reliable, m *channels.Muxer, exec_ch *codex.ExecChan) {
	logrus.SetOutput(io.Discard)
	exec_ch.Restore()
	intent, err := ReadIntentRequest(agc)
	if err != nil {
		logrus.Fatalf("ERROR READING INTENT REQUEST: %v", err)
	}

	logrus.Info("C: PRINCIPAL REC: INTENT_REQUEST")
	req := FromIntentRequestBytes(intent[TYPE_LEN:])

	exec_ch.ClosePipe()

	req.Display()
	var resp string
	fmt.Scanln(&resp) //TODO:Fix and make sure this is safe/sanitize input/make this a popup instead.

	exec_ch.Pipe()
	exec_ch.Raw()

	if resp == "yes" {
		logrus.Info("C: USER CONFIRMED INTENT_REQUEST. CONTACTING S2...") //TODO: ACTUALLY DO THE NPC THING

		//create npc with server1
		npcCh, e := m.CreateChannel(channels.NPC_CHANNEL)
		if e != nil {
			logrus.Fatal("C: Error starting NPC")
		}
		addr := req.serverSNI + ":" + strconv.Itoa(int(req.port))
		npcCh.Write(npc.NewNPCInitMsg(addr).ToBytes())
		npcCh.Read(make([]byte, 1))
		logrus.Info("Receieved NPC Conf")
		tclient, e := transport.DialNPC("npc", addr, npcCh, nil)
		if e != nil {
			logrus.Fatal("error dialing npc")
		}
		e = tclient.Handshake()
		if e != nil {
			logrus.Fatal("Handshake failed: ", e)
		}
		logrus.Info("handshake successful")
		npc_muxer := channels.NewMuxer(tclient, tclient)
		go npc_muxer.Start()
		//defer npc_muxer.Stop()

		npc_agc, e := npc_muxer.CreateChannel(channels.AGC_CHANNEL)
		if e != nil {
			logrus.Fatal("Error creating AGC: ", e)
		}
		logrus.Info("CREATED AGC")
		_, e = npc_agc.Write(CommFromReq(intent))
		if e != nil {
			logrus.Info("Issue writing intent comm to npc_agc")
		}
		response, _, e := GetResponse(npc_agc)
		logrus.Info("got response")
		if e != nil {
			logrus.Fatalf("C: error reading from agc: %v", e)
		}
		_, err = agc.Write(response)
		if err != nil {
			logrus.Fatalf("C: error writing to agc: %v", err)
		}
		logrus.Infof("C: WROTE INTENT_CONFIRMATION")
		npc_agc.Close()

		// Want to keep this session open in case the "server 2" wants to continue chaining hop sessions together
		// Should only get authorization grant channels?
		// wg := sync.WaitGroup{}
		// wg.Add(1)
		go func() {
			//defer wg.Done()
			for {
				c, e := npc_muxer.Accept()
				if e != nil {
					logrus.Fatalf("Error accepting channel: ", e)
				}
				logrus.Infof("Accepted channel of type: %v", c.Type())
				if c.Type() == channels.AGC_CHANNEL {
					go Principal(c, npc_muxer, exec_ch)
				} else if c.Type() == channels.NPC_CHANNEL {
					//go do something?
				} else if c.Type() == channels.EXEC_CHANNEL {
					//go do something else?
				} else {
					//bad channel
					c.Close()
					continue
				}
			}
		}()
		//wg.Wait()
	} else {
		agc.Write(NewIntentDenied("User denied.").ToBytes())
	}
}

//Go routine for Server to handle an INTENT_COMMUNICATION from a principal
func Server(agc *channels.Reliable, muxer *channels.Muxer, agToMux map[string]*channels.Muxer) {
	logrus.Info("waiting for intent communication")
	defer agc.Close()
	msg, e := ReadIntentCommunication(agc)
	if e != nil {
		logrus.Fatalf("error reading intent communication")
	}
	//CHECK POLICY
	//SET DEADLINE
	//STORE AG INFORMATION
	intent := FromIntentCommunicationBytes(msg[TYPE_LEN:])
	logrus.Infof("Pretending s2 approved intent request")
	t := time.Time(time.Now().Add(time.Duration(time.Hour))) //TODO: This should be set by server 2
	f, err := os.OpenFile("../app/authorized_keys", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		logrus.Fatalf("error opening authorized keys file: ", err)
	}
	defer f.Close()
	k := keys.PublicKey(intent.sha3)
	logrus.Infof("Added: %v", k.String())
	authgrant := fmt.Sprintf("%v %v %v %v %v", k.String(), 0, t.String(), "user", strings.Join(intent.action, " "))
	_, e = f.WriteString(authgrant)
	f.WriteString("\n")
	if e != nil {
		logrus.Infof("Issue writing to authorized keys file: ", e)
	}
	agToMux[authgrant] = muxer
	logrus.Infof("Added: %v with Value: %v", authgrant, agToMux[authgrant])

	agc.Write(NewIntentConfirmation(t).ToBytes())
	agc.Close()
}

func (r *IntentRequest) Display() {
	fmt.Printf("Allow %v@%v to run %v on %v@%v? \nEnter yes or no: ",
		r.clientUsername,
		r.clientSNI,
		r.action,
		r.serverUsername,
		r.serverSNI)
}
