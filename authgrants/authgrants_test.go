package authgrants

import (
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
		GrantType:      grantType(ShellAction),
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
