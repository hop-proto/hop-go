package authgrants

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"hop.computer/hop/certs"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
)

func checkAgMessage(t *testing.T, msg AgMessage) bool {
	switch msg.MsgType {
	case IntentRequest:
		_, ok := msg.Data.(Intent)
		return ok
	case IntentCommunication:
		_, ok := msg.Data.(Intent)
		return ok
	case IntentDenied:
		_, ok := msg.Data.(Denial)
		return ok
	case IntentConfirmation:
		ok := msg.Data == nil
		return ok
	}
	return false
}

func TestEnc(t *testing.T) {
	var network bytes.Buffer // Stand-in for a network connection
	gob.Register(Intent{})
	gob.Register(Denial{})
	gob.Register(CommandGrantData{})

	enc := gob.NewEncoder(&network) // Will write to network.
	dec := gob.NewDecoder(&network) // Will read from network.

	target := certs.DNSName("github.com")
	cert, err := new(certs.Certificate).Marshal()
	assert.NilError(t, err)

	intent := Intent{
		GrantType:      Shell,
		Reserved:       0,
		TargetPort:     55,
		StartTime:      time.Now().Unix(),
		ExpTime:        time.Now().Add(time.Hour).Unix(),
		TargetUsername: "laura",
		TargetSNI:      target,
		DelegateCert:   cert,
		AssociatedData: CommandGrantData{"echo hello world"},
	}

	denial := Denial{"invalid request"}

	goodMsgs := [4]AgMessage{{IntentCommunication, intent}, {IntentRequest, intent}, {IntentConfirmation, nil}, {IntentDenied, denial}}
	for _, msg := range goodMsgs {
		err = enc.Encode(msg)
		assert.NilError(t, err)
		var recMsg AgMessage
		err = dec.Decode(&recMsg)
		assert.NilError(t, err)
		assert.Equal(t, true, checkAgMessage(t, recMsg))
	}

	malformedMsgs := [4]AgMessage{{IntentCommunication, nil}, {IntentRequest, denial}, {IntentConfirmation, intent}, {IntentDenied, intent}}
	for _, msg := range malformedMsgs {
		err = enc.Encode(msg)
		assert.NilError(t, err)
		var recMsg AgMessage
		err = dec.Decode(&recMsg)
		assert.NilError(t, err)
		assert.Equal(t, false, checkAgMessage(t, recMsg))
	}
}

func TestIntentRequest(t *testing.T) {
	wg := sync.WaitGroup{}
	logrus.SetLevel(logrus.DebugLevel)
	tcpListener, err := net.Listen("tcp", "localhost:0")
	assert.NilError(t, err)

	clientConn, err := net.Dial("tcp", tcpListener.Addr().String())
	assert.NilError(t, err)
	clientEnc := gob.NewEncoder(clientConn)

	serverConn, err := tcpListener.Accept()
	assert.NilError(t, err)
	serverDec := gob.NewDecoder(serverConn)
	defer serverConn.Close()

	target := certs.DNSName("github.com")
	cert, err := new(certs.Certificate).Marshal()
	assert.NilError(t, err)

	intent := Intent{
		GrantType:      Shell,
		Reserved:       0,
		TargetPort:     55,
		StartTime:      time.Now().Unix(),
		ExpTime:        time.Now().Add(time.Hour).Unix(),
		TargetUsername: "laura",
		TargetSNI:      target,
		DelegateCert:   cert,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Printf("intent: %v\n", intent)
		err = clientEnc.Encode(intent)
		assert.NilError(t, err)
	}()

	var recIntent Intent
	fmt.Printf("%p\n", &recIntent)
	fmt.Printf("%p\n", &intent)
	wg.Wait()
	err = serverDec.Decode(&recIntent)
	fmt.Printf("recIntent: %v\n", recIntent)
	assert.DeepEqual(t, intent, recIntent)

}
