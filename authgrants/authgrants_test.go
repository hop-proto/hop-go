package authgrants

import (
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"zmap.io/portal/certs"
	"zmap.io/portal/keys"
	"zmap.io/portal/transport"
	"zmap.io/portal/tubes"
)

const testDataPathPrefix = "../transport/"

//NewTestServerConfig populates server config and verify config with sample cert data
func newTestServerConfig(testDataPathPrefix string) (*transport.ServerConfig, *transport.VerifyConfig) {
	keyPair, err := keys.ReadDHKeyFromPEMFile(testDataPathPrefix + "testdata/leaf-key.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH KEYPAIR %v", err)
	}
	certificate, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/leaf.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH CERTS %v", err)
	}
	intermediate, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/intermediate.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH INT CERTS %v", err)
	}
	root, err := certs.ReadCertificatePEMFile(testDataPathPrefix + "testdata/root.pem")
	if err != nil {
		logrus.Fatalf("S: ERROR WITH ROOT CERT %v", err)
	}
	err = certs.VerifyParent(certificate, intermediate)
	if err != nil {
		logrus.Fatal("Verify Parent Issue: ", err)
	}
	err = certs.VerifyParent(intermediate, root)
	if err != nil {
		logrus.Fatal("Verify Parent Issue: ", err)
	}
	err = certs.VerifyParent(root, root)
	if err != nil {
		logrus.Fatal("Verify Parent Issue: ", err)
	}

	server := transport.ServerConfig{
		KeyPair:      keyPair,
		Certificate:  certificate,
		Intermediate: intermediate,
	}
	verify := transport.VerifyConfig{
		Store: certs.Store{},
	}
	verify.Store.AddCertificate(root)
	return &server, &verify
}

func getInsecureClientConfig() transport.ClientConfig {
	return transport.ClientConfig{
		Verify: transport.VerifyConfig{
			InsecureSkipVerify: true,
		},
	}
}

func TestIntentRequest(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	pktConn, err := net.ListenPacket("udp", "localhost:1234")
	assert.NilError(t, err)
	// It's actually a UDP conn
	udpConn := pktConn.(*net.UDPConn)
	s, _ := newTestServerConfig(testDataPathPrefix)
	server, err := transport.NewServer(udpConn, s)
	assert.NilError(t, err)
	go server.Serve()

	transportConn, err := transport.Dial("udp", udpConn.LocalAddr().String(), getInsecureClientConfig())
	assert.NilError(t, err)

	assert.NilError(t, transportConn.Handshake())

	serverConn, err := server.AcceptTimeout(time.Minute)
	assert.NilError(t, err)

	mc := tubes.NewMuxer(transportConn, transportConn)
	go mc.Start()

	agc, err := NewAuthGrantConnFromMux(mc)
	assert.NilError(t, err)

	ms := tubes.NewMuxer(serverConn, serverConn)
	go ms.Start()

	stube, err := ms.Accept()
	assert.NilError(t, err)
	sagc := &AuthGrantConn{conn: stube}

	go func() {
		ir := newIntent([32]byte{}, "user", "host", "port", 2, "myCmd")
		logrus.Info("C: Made req: \n",
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
			logrus.Info("C: Got conf with deadline: ", fromIntentConfirmationBytes(response).deadline)
		case IntentDenied:
			logrus.Info("C: Got den with reason: ", fromIntentDeniedBytes(response).reason)
		}
		agc.Close()
	}()

	ir, err := sagc.GetIntentRequest()
	assert.NilError(t, err)
	logrus.Info("S: Got req: \n",
		"clientsni: ", ir.clientSNI, " ",
		"client user: ", ir.clientUsername, " ",
		"port: ", ir.port, " ",
		"serversni: ", ir.serverSNI, " ",
		"serverUser: ", ir.serverUsername, " ",
		"grantType: ", ir.actionType, " ",
		"sha3: ", ir.sha3)
	//err = SendIntentConf(stube, time.Now())
	err = sagc.SendIntentDenied("because I say so")
	assert.NilError(t, err)
	stube.Close()

}
