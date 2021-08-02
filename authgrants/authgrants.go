//Package providing support for the authorization grant protocol.
package authgrants

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sbinet/pstree"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"zmap.io/portal/channels"
	"zmap.io/portal/codex"
	"zmap.io/portal/keys"
	"zmap.io/portal/npc"
	"zmap.io/portal/transport"
)

//Used by Client to get an authorization grant from its Principal
func GetAuthGrant(digest [SHA3_LEN]byte, sUser string, addr string, cmd []string) (int64, error) {
	intent := NewIntentRequest(digest, sUser, addr, cmd)
	sock := "/tmp/auth.sock" //TODO(baumanl): make generalizeable
	if addr == "127.0.0.1:9999" {
		sock = "/tmp/auth2.sock"
	}
	c, err := net.Dial("unix", sock) //TODO(baumanl): address of UDS (probably switch to abstract location)
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

	//TODO(baumanl): SET TIMEOUT STUFF + BETTER ERROR CHECKING
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

//Used by Principal to respond to INTENT_REQUESTS from a Client
func Principal(agc *channels.Reliable, m *channels.Muxer, exec_ch *codex.ExecChan) {
	logrus.SetOutput(io.Discard)
	exec_ch.Restore()
	intent, err := ReadIntentRequest(agc)
	if err != nil {
		logrus.Fatalf("ERROR READING INTENT REQUEST: %v", err)
	}

	logrus.Info("C: PRINCIPAL REC: INTENT_REQUEST")
	req := FromIntentRequestBytes(intent[TYPE_LEN:])

	//TODO(baumanl): FIX THIS!
	//This still doesn't work great for getting user input to principal.
	//User has to hit enter once and then actually provide your input.
	//(i.e. the first time the user provides input and presses enter the principal does not receive the input
	//and I'm assuming it is still being sent to the server over the code execution channel)
	//Can't figure out how to stop the io.Copy() that takes Stdin -> exec_ch to stop without this issue.
	//Tried simulating user input by sending keystrokes to /dev/uinput, but that
	//	1.) requires sudo priv of principal (bad) and
	// 	2.) didn't even seem to fix the issue
	exec_ch.ClosePipe()
	req.Display()
	var resp string
	fmt.Scanln(&resp) //TODO(baumanl):Replace this with a better format question/response like "github.com/tockins/interact"

	exec_ch.Pipe()
	exec_ch.Raw()

	if resp == "yes" {
		logrus.Info("C: USER CONFIRMED INTENT_REQUEST. CONTACTING S2...")

		//create npc with server
		npcCh, e := m.CreateChannel(channels.NPC_CHANNEL)
		if e != nil {
			logrus.Fatal("C: Error starting NPC")
		}
		addr := req.serverSNI + ":" + strconv.Itoa(int(req.port))
		npcCh.Write(npc.NewNPCInitMsg(addr).ToBytes()) //tell server to prepare to proxy to addr (start a UDP conn)

		//TODO(baumanl): Make better conf/denial messages for NPC
		//wait until server says it has a UDP conn to desired address
		npcCh.Read(make([]byte, 1))
		logrus.Info("Receieved NPC Conf")

		//start hop session over NPC
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

		//start AGC and send INTENT_COMMUNICATION
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

		//write response back to server asking for Authorization Grant
		_, err = agc.Write(response)
		if err != nil {
			logrus.Fatalf("C: error writing to agc: %v", err)
		}
		//TODO(baumanl): Add logic to deal with potential INTENT_DENIED from server
		logrus.Infof("C: WROTE INTENT_CONFIRMATION")
		npc_agc.Close()

		// Want to keep this session open in case the "server 2" wants to continue chaining hop sessions together
		// TODO(baumanl): Simplify this. Should only get authorization grant channels?
		go func() {
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
					c.Close()
				} else if c.Type() == channels.EXEC_CHANNEL {
					//go do something else?
					c.Close()
				} else {
					//bad channel
					c.Close()
				}
			}
		}()
	} else {
		agc.Write(NewIntentDenied("User denied.").ToBytes())
	}
}

//Used by Server to handle an INTENT_COMMUNICATION from a Principal
func Server(agc *channels.Reliable, muxer *channels.Muxer, agToMux map[string]*channels.Muxer) {
	logrus.Info("waiting for intent communication")
	defer agc.Close()
	msg, e := ReadIntentCommunication(agc)
	if e != nil {
		logrus.Fatalf("error reading intent communication")
	}
	intent := FromIntentCommunicationBytes(msg[TYPE_LEN:])
	logrus.Infof("Pretending s2 approved intent request")                                   //TODO(baumanl): check policy or something?
	t := time.Time(time.Now().Add(time.Duration(time.Hour)))                                //TODO(baumanl): What should this actually be? (probably much shorter)
	f, err := os.OpenFile("../app/authorized_keys", os.O_APPEND|os.O_WRONLY, os.ModeAppend) //TODO(baumanl): fix authorized_keys file location
	if err != nil {
		logrus.Fatalf("error opening authorized keys file: ", err)
	}
	defer f.Close()
	k := keys.PublicKey(intent.sha3)
	logrus.Infof("Added: %v", k.String())
	//authgrant format: <static key> <deadline> <username> <action>
	authgrant := fmt.Sprintf("%v %v %v %v", k.String(), t.Unix(), strings.TrimSpace(intent.serverUsername), strings.Join(intent.action, " "))
	_, e = f.WriteString(authgrant)
	f.WriteString("\n")
	if e != nil {
		logrus.Infof("Issue writing to authorized keys file: ", e)
	}
	agToMux[k.String()] = muxer

	agc.Write(NewIntentConfirmation(t).ToBytes())
	agc.Close()
}

//Used by Server to forward INTENT_REQUESTS from a Client -> Principal and responses from Principal -> Client
//Checks hop client process is a descendent of the hop server and conducts authgrant request with the appropriate principal
func ProxyAuthGrantRequest(c net.Conn, principals *map[int32]*channels.Muxer) {
	//TODO(baumanl): check threadsafety
	logrus.Info("S: ACCEPTED NEW UDS CONNECTION")
	defer c.Close()
	//Verify that the client is a legit descendent
	ancestor, e := checkCredentials(c, principals)
	if e != nil {
		log.Fatalf("S: ISSUE CHECKING CREDENTIALS: %v", e)
	}
	// find corresponding session muxer
	principal := (*principals)[ancestor]
	logrus.Infof("S: CLIENT CONNECTED [%s]", c.RemoteAddr().Network())
	intent, e := ReadIntentRequest(c)
	if e != nil {
		logrus.Fatalf("ERROR READING INTENT REQUEST: %v", e)
	}
	agc, err := principal.CreateChannel(channels.AGC_CHANNEL)
	if err != nil {
		logrus.Fatalf("S: ERROR MAKING CHANNEL: %v", err)
	}
	logrus.Infof("S: CREATED CHANNEL (AGC)")
	_, err = agc.Write(intent)
	if err != nil {
		logrus.Fatalf("S: ERROR WRITING TO CHANNEL: %v", err)
	}
	logrus.Infof("S: WROTE INTENT_REQUEST TO AGC")
	response, _, err := GetResponse(agc)
	if err != nil {
		logrus.Fatalf("S: ERROR GETTING RESPONSE: %v, %v", err, response)
	}
	_, err = c.Write(response)
	if err != nil {
		logrus.Fatalf("S: ERROR WRITING TO CHANNEL: %v", err)
	}

	//TODO(baumanl): Add retry logic if INTENT_DENIED
	// if response[0] == INTENT_DENIED {
	// 	//ASK USER IF THEY WANT TO TRY AGAIN BEFORE CLOSING AGC
	// }
}

//Print authgrant approval prompt to terminal
func (r *IntentRequest) Display() {
	fmt.Printf("\nAllow %v@%v to run %v on %v@%v? \nEnter yes or no: \n (Bug: hit enter once before responding)",
		r.clientUsername,
		r.clientSNI,
		r.action,
		r.serverUsername,
		r.serverSNI)
}

//checks tree (starting at proc) to see if cPID is a descendent
func checkDescendents(tree *pstree.Tree, proc pstree.Process, cPID int) bool {
	for _, child := range proc.Children {
		if child == cPID || checkDescendents(tree, tree.Procs[child], cPID) {
			return true
		}
	}
	return false
}

//verifies that client is a descendent of a process started by the principal and returns its ancestor process PID if found
func checkCredentials(c net.Conn, principals *map[int32]*channels.Muxer) (int32, error) {
	creds, err := readCreds(c)
	if err != nil {
		return 0, err
	}
	//PID of client process that connected to socket
	cPID := creds.Pid
	//ancestor represents the PID of the ancestor of the client and child of server daemon
	var ancestor int32 = -1
	//get a picture of the entire system process tree
	tree, err := pstree.New()
	//display(os.Getppid(), tree, 1) //displays all pstree
	if err != nil {
		return 0, err
	}
	//check all of the PIDs of processes that the server started
	for k := range *principals {
		if k == cPID || checkDescendents(tree, tree.Procs[int(k)], int(cPID)) {
			ancestor = k
			break
		}
	}
	if ancestor == -1 {
		return 0, errors.New("not a descendent process")
	}
	logrus.Info("S: CREDENTIALS VERIFIED")
	return ancestor, nil
}

//Src: https://blog.jbowen.dev/2019/09/using-so_peercred-in-go/src/peercred/cred.go
//Parses the credentials sent by the client when it connects to the socket
func readCreds(c net.Conn) (*unix.Ucred, error) {
	var cred *unix.Ucred

	//should only have *net.UnixConn types
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("unexpected socket type")
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("error opening raw connection: %s", err)
	}

	// The raw.Control() callback does not return an error directly.
	// In order to capture errors, we wrap already defined variable
	// 'err' within the closure. 'err2' is then the error returned
	// by Control() itself.
	err2 := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED)
	})

	if err != nil {
		return nil, fmt.Errorf(" GetsockoptUcred() error: %s", err)
	}

	if err2 != nil {
		return nil, fmt.Errorf(" Control() error: %s", err2)
	}

	return cred, nil
}
