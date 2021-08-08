//Package authgrants provides support for the authorization grant protocol.
package authgrants

import (
	"bufio"
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

//GetAuthGrant is used by the Client to get an authorization grant from its Principal
func GetAuthGrant(digest [sha3Len]byte, sUser string, addr string, cmd []string) (int64, error) {
	intent := newIntentRequest(digest, sUser, addr, cmd)
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
	_, e := c.Write(intent.toBytes())
	if e != nil {
		logrus.Fatal("C: error writing to UDS")
	}
	logrus.Infof("C: WROTE INTENT TO UDS")
	response, resptype, err := getResponse(c)
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
	intent, err := readIntentRequest(agc)
	if err != nil {
		logrus.Fatalf("ERROR READING INTENT REQUEST: %v", err)
	}

	logrus.Info("C: PRINCIPAL REC: INTENT_REQUEST")
	req := fromIntentRequestBytes(intent[TypeLen:])

	//TODO(baumanl): FIX THIS!
	//This still doesn't work great for getting user input to principal.
	//User has to hit enter once and then actually provide your input.
	//(i.e. the first time the user provides input and presses enter the principal does not receive the input
	//and I'm assuming it is still being sent to the server over the code execution channel)
	//Can't figure out how to stop the io.Copy() that takes Stdin -> execCh to stop without this issue.
	//Tried simulating user input by sending keystrokes to /dev/uinput, but that
	//	1.) requires sudo priv of principal (bad) and
	// 	2.) didn't even seem to fix the issue
	execCh.Restore()
	logrus.SetOutput(os.Stdout)
	r := execCh.Redirect()
	req.Display()
	scanner := bufio.NewScanner(r)
	scanner.Scan()
	resp := scanner.Text() //TODO(baumanl):Replace this with a better format question/response like "github.com/tockins/interact"
	execCh.Raw()
	execCh.Resume()
	logrus.SetOutput(io.Discard)
	if resp == "yes" {
		logrus.Info("C: USER CONFIRMED INTENT_REQUEST. CONTACTING S2...")

		//create npc with server
		npcCh, e := m.CreateChannel(channels.NPC_CHANNEL) //How do I close this on the principal side?
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

		//start AGC and send INTENT_COMMUNICATION
		npcAgc, e := npcMuxer.CreateChannel(channels.AGC_CHANNEL)
		if e != nil {
			logrus.Fatal("Error creating AGC: ", e)
		}
		logrus.Info("CREATED AGC")
		_, e = npcAgc.Write(commFromReq(intent))
		if e != nil {
			logrus.Info("Issue writing intent comm to npcAgc")
		}
		response, _, e := getResponse(npcAgc)
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
				if c.Type() == channels.AGC_CHANNEL {
					go Principal(c, npcMuxer, execCh, config)
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

//ProxyAuthGrantRequest is used by Server to forward INTENT_REQUESTS from a Client -> Principal and responses from Principal -> Client
//Checks hop client process is a descendent of the hop server and conducts authgrant request with the appropriate principal
func ProxyAuthGrantRequest(c net.Conn, principals map[int32]*transport.Handle, sessions map[*transport.Handle]*channels.Muxer) {
	//TODO(baumanl): check threadsafety
	logrus.Info("S: ACCEPTED NEW UDS CONNECTION")
	defer c.Close()
	//Verify that the client is a legit descendent
	ancestor, e := checkCredentials(c, principals)
	if e != nil {
		log.Fatalf("S: ISSUE CHECKING CREDENTIALS: %v", e)
	}
	// find corresponding session muxer
	handle := principals[ancestor]
	if handle.IsClosed() {
		logrus.Info("Connection with Principal is closed")
		return
	}
	principal := sessions[handle]
	logrus.Infof("S: CLIENT CONNECTED [%s]", c.RemoteAddr().Network())
	intent, e := readIntentRequest(c)
	if e != nil {
		logrus.Fatalf("ERROR READING INTENT REQUEST: %v", e)
	}
	agc, err := principal.CreateChannel(channels.AGC_CHANNEL)
	if err != nil {
		logrus.Fatalf("S: ERROR MAKING CHANNEL: %v", err)
	}
	defer agc.Close()
	logrus.Infof("S: CREATED CHANNEL (AGC)")
	_, err = agc.Write(intent)
	if err != nil {
		logrus.Fatalf("S: ERROR WRITING TO CHANNEL: %v", err)
	}
	logrus.Infof("S: WROTE INTENT_REQUEST TO AGC")
	response, _, err := getResponse(agc)
	if err != nil {
		logrus.Fatalf("S: ERROR GETTING RESPONSE: %v, %v", err, response)
	}
	_, err = c.Write(response)
	if err != nil {
		logrus.Fatalf("S: ERROR WRITING TO CHANNEL: %v", err)
	}

	//TODO(baumanl): Add retry logic if IntentDenied
	// if response[0] == IntentDenied {
	// 	//ASK USER IF THEY WANT TO TRY AGAIN BEFORE CLOSING AGC
	// }
}

//Display prints the authgrant approval prompt to terminal
func (r *intentRequestMsg) Display() {
	fmt.Printf("\nAllow %v@%v to run %v on %v@%v? \nEnter yes or no: ",
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
func checkCredentials(c net.Conn, principals map[int32]*transport.Handle) (int32, error) {
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
	for k := range principals {
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
