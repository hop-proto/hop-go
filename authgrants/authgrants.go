package authgrants

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
	"zmap.io/portal/channels"
	"zmap.io/portal/exec_channels"
	"zmap.io/portal/npc"
	"zmap.io/portal/transport"
)

/*Used by Client Process to get an authorization grant from its Principal*/
func GetAuthGrant(digest [SHA3_LEN]byte, sUser string, addr string, cmd []string) (int64, error) {
	intent := NewIntentRequest(digest, sUser, addr, cmd)
	c, err := net.Dial("unix", "/tmp/auth.sock") //TODO: address of UDS
	if err != nil {
		logrus.Fatal(err)
	}

	defer c.Close()
	logrus.Infof("C: CONNECTED TO UDS: [%v]", c.RemoteAddr().String())
	c.Write(intent.ToBytes())

	response, err := GetResponse(c)
	if err != nil {
		logrus.Fatalf("S: ERROR GETTING RESPONSE: %v", err)
	}

	//TODO: SET TIMEOUT STUFF + BETTER ERROR CHECKING
	if response[0] == INTENT_CONFIRMATION {
		return FromIntentConfirmationBytes(response[TYPE_LEN:]).Deadline, nil
	} else if response[0] == INTENT_DENIED {
		reason := FromIntentDeniedBytes(response[TYPE_LEN:]).reason
		logrus.Infof("Reason for denial: %v", reason)
		return 0, errors.New("principal denied Intent Request")
	}
	return 0, errors.New("received message with unknown message type")
}

/*Go routine for Principal to respond to auth grant requests*/
func Principal(agc *channels.Reliable, m *channels.Muxer, state *terminal.State) {
	exec_channels.RestoreTerm(state)
	intent, err := ReadIntentRequest(agc)
	if err != nil {
		logrus.Fatalf("ERROR READING INTENT REQUEST: %v", err)
	}
	logrus.Info("C: PRINCIPAL REC: INTENT_REQUEST")
	req := FromIntentRequestBytes(intent[TYPE_LEN:])
	req.Display()
	fmt.Println("Pretending user said yes...")
	resp := "yes"
	//var resp string
	//fmt.Scanln(&resp) //TODO:Fix and make sure this is safe/sanitize input/make this a popup instead.
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
		tclient, e := transport.DialNPC("npc", addr, npcCh)
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
		defer npc_muxer.Stop()

		npc_agc, e := npc_muxer.CreateChannel(channels.AGC_CHANNEL)
		if e != nil {
			logrus.Fatal("Error creating AGC: ", e)
		}
		logrus.Info("CREATED AGC")
		_, e = npc_agc.Write(CommFromReq(intent))
		if e != nil {
			logrus.Info("Issue writing intent comm to npc_agc")
		}
		response, e := GetResponse(npc_agc)
		logrus.Info("got response")
		if e != nil {
			logrus.Fatalf("C: error reading from agc: %v", e)
		}
		_, err = agc.Write(response)
		if err != nil {
			logrus.Fatalf("C: error writing to agc: %v", err)
		}
		logrus.Infof("C: WROTE INTENT_CONFIRMATION")
	} else {
		agc.Write(NewIntentDenied("User denied.").ToBytes())
	}
}

//Go routine for Server to handle an INTENT_COMMUNICATION from a principal
func Server(agc *channels.Reliable) {
	logrus.Info("waiting for intent communication")
	_, e := ReadIntentCommunication(agc)
	if e != nil {
		logrus.Fatalf("error reading intent communication")
	}
	//CHECK POLICY
	//SET DEADLINE
	//STORE AG INFORMATION
	logrus.Infof("Pretending s2 approved intent request")
	t := time.Time(time.Now().Add(time.Duration(time.Hour))) //TODO: This should be set by server 2
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
