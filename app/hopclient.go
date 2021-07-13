package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"zmap.io/portal/authgrants"
	"zmap.io/portal/channels"
	"zmap.io/portal/exec_channels"
	"zmap.io/portal/transport"
)

func startClient(args []string) {
	logrus.SetLevel(logrus.InfoLevel)

	//******PROCESS ARGUMENTS******
	if len(args) < 5 {
		logrus.Fatal("C: Invalid arguments. Useage: hop user@host:port -k <pathtokey> or hop user@host:port -a <action>.")
	}
	s := strings.SplitAfter(args[2], "@") //TODO: Add support for optional username
	user := s[0][0 : len(s[0])-1]
	addr := s[1]
	cmd := []string{"bash"} //default action for principal is to open an interactive shell

	//Check if this is a principal client process or one that needs to get an AG
	//******GET AUTHORIZATION SOURCE******
	if args[3] == "-k" {
		logrus.Infof("C: Using key-file at %v for auth.", args[4])
		//TODO: actually do this somehow???
	} else if args[3] == "-a" {
		logrus.Infof("C: Initiating AGC Protocol.")
		//TODO: generate keypair and store somehow
		digest := sha3.Sum256([]byte("pubkey")) //don't know if this is correct
		cmd = args[4:]                          //if using authorization grant then perform the action specified in cmd line
		t, e := authgrants.GetAuthGrant(digest, user, addr, cmd)
		if e != nil {
			logrus.Fatalf("C: %v", e)
		}
		logrus.Infof("C: Principal approved request. Deadline: %v", t)
		//TODO: potentially store the deadline somewhere?
	}

	//******ESTABLISH HOP SESSION******
	//TODO: figure out addr format requirements + check for them above
	transportConn, err := transport.Dial("udp", addr, nil) //There seem to be limits on Dial() and addr format
	if err != nil {
		logrus.Fatalf("C: error dialing server: %v", err)
	}
	err = transportConn.Handshake()
	if err != nil {
		logrus.Fatalf("C: Issue with handshake: %v", err)
	}
	//TODO: should these functions + things from Channels layer have errors?
	mc := channels.NewMuxer(transportConn, transportConn)
	go mc.Start()
	defer mc.Stop()

	//*****RUN COMMAND (BASH OR AG ACTION)*****
	logrus.Infof("Performing action: %v", cmd)
	ch, _ := mc.CreateChannel(channels.EXEC_CHANNEL)
	wg := sync.WaitGroup{}
	wg.Add(1)
	state := exec_channels.MakeRawTerm()
	defer exec_channels.RestoreTerm(state)
	go exec_channels.Client(ch, cmd, &wg)
	//if this is a principal process start listening for AGC
	if args[3] == "-k" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			agc, err := mc.Accept()
			if err != nil {
				logrus.Fatalf("C: issue accepting channel: %v", err)
			}
			exec_channels.RestoreTerm(state)
			if err != nil {
				fmt.Printf("C: error closing channel: %v", err)
			}
			if agc.Type() != channels.AGC_CHANNEL {
				logrus.Info("C: Unexpected channel")
				return
			}
			agc_buf := make([]byte, authgrants.IR_HEADER_LENGTH+1)
			n, err := agc.Read(agc_buf)

			logrus.Infof("Read %v bytes", n)
			if err != nil {
				logrus.Fatalf("C: issue reading from channel: %v", err)
			}
			logrus.Infof("buf[0]: %v and INTENT_REQUEST: %v", agc_buf[0], authgrants.INTENT_REQUEST)
			if agc_buf[0] == authgrants.INTENT_REQUEST {
				logrus.Info("C: PRINCIPAL REC: INTENT_REQUEST")
				a := make([]byte, int(agc_buf[len(agc_buf)-1]))
				agc.Read(a)
				req := authgrants.FromIntentRequestBytes(append(agc_buf, a...))
				req.Display()
				fmt.Println("Pretending user said yes...")
				resp := "yes"
				// var resp string
				// fmt.Scanln(&resp) //TODO:Fix and make sure this is safe/sanitize input/make this a popup instead.
				if resp == "yes" {
					logrus.Info("C: USER CONFIRMED INTENT_REQUEST. CONTACTING S2...") //TODO: ACTUALLY DO THE NPC THING
					//create npc with server1
					// npcCh, _ := mc.CreateChannel(1 << 8)
					// i := npc.NewNPCInitMsg("127.0.0.1", "9999")
					// npcCh.Write(i.ToBytes())

					logrus.Info("C: PRETENDING S2 SAID YES")
					t := time.Time(time.Now().Add(time.Duration(time.Hour)))
					s := authgrants.NewIntentConfirmation(t)
					_, err = agc.Write(s.ToBytes())
					if err != nil {
						logrus.Fatalf("C: error writing to agc: %v", err)
					}
					logrus.Infof("C: WROTE INTENT_CONFIRMATION")
				} else {
					s := authgrants.NewIntentDenied("User Denial.")
					n, err = agc.Write(s.ToBytes())
					logrus.Infof("C: WROTE %v BYTES OF INTENT DENIED", n)
					logrus.Infof("C: INTENT_DENIED: %v", s.ToBytes())
					if err != nil {
						logrus.Fatalf("C: error writing to agc: %v", err)
					}
					logrus.Info("C: INTENT DENIED")
				}
			}
		}()
	}
	wg.Wait()
	logrus.Infof("All done!")
}
