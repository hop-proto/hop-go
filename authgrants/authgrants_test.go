package authgrants

import (
	"net"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"zmap.io/portal/ports"
)

var start = 17000

var portMutex = sync.Mutex{}

func port() string {
	portMutex.Lock()
	port, next := ports.GetPortNumber(start)
	start = next
	portMutex.Unlock()
	return port
}

func TestIntentRequest(t *testing.T) {
	wg := sync.WaitGroup{}
	logrus.SetLevel(logrus.DebugLevel)
	port := port()
	tcpListener, err := net.Listen("tcp", net.JoinHostPort("localhost", port))
	assert.NilError(t, err)

	clientConn, err := net.Dial("tcp", ":"+port)
	assert.NilError(t, err)

	serverConn, err := tcpListener.Accept()
	assert.NilError(t, err)
	defer serverConn.Close()

	agc := NewAuthGrantConn(clientConn)

	sagc := &AuthGrantConn{conn: serverConn}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ir := newIntent([32]byte{}, "user", "host", "port", 2, "myCmd")
		logrus.Info("C: Made req: ",
			"clientsni: ", ir.clientSNI, " ",
			"client user: ", ir.clientUsername, " ",
			"port: ", ir.port, " ",
			"serversni: ", ir.serverSNI, " ",
			"serverUser: ", ir.serverUsername, " ",
			"grantType: ", ir.actionType, " ",
			"sha3: ", ir.sha3)
		err := agc.sendIntentRequest([32]byte{}, "user", "host", "port", 2, "myCmd")
		assert.NilError(t, err)
		logrus.Info("Sent req ok")
		rtype, response, err := agc.ReadResponse()
		assert.NilError(t, err)
		switch rtype {
		case IntentConfirmation:
			logrus.Info("C: Got conf with deadline: ", fromIntentConfirmationBytes(response[dataOffset:]).deadline)
		case IntentDenied:
			logrus.Infof("C: Got den with reason: %v", fromIntentDeniedBytes(response[dataOffset:]).reason)
			assert.Equal(t, fromIntentDeniedBytes(response[dataOffset:]).reason, "because I say so")
		}
		agc.Close()
	}()

	ir, err := sagc.GetIntentRequest()
	assert.NilError(t, err)
	logrus.Info("S: Got req: ",
		"clientsni: ", ir.clientSNI, " ",
		"client user: ", ir.clientUsername, " ",
		"port: ", ir.port, " ",
		"serversni: ", ir.serverSNI, " ",
		"serverUser: ", ir.serverUsername, " ",
		"grantType: ", ir.actionType, " ",
		"sha3: ", ir.sha3)
	//err = sagc.SendIntentConf(time.Now())
	err = sagc.SendIntentDenied("because I say so")
	assert.NilError(t, err)
	wg.Wait()
}
