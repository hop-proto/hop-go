package authgrants

import (
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"gotest.tools/assert"

	"hop.computer/hop/certs"
	"hop.computer/hop/core"
)

func getTestCmdIntentRequest(t *testing.T, cmd string) AgMessage {
	startTime := time.Now().Unix()
	expTime := time.Now().Add(time.Hour).Unix()
	var testKeyPair keypair
	rand.Read(testKeyPair.public[:])
	rand.Read(testKeyPair.private[:])
	msg := AgMessage{
		MsgType: IntentRequest,
		Data: MessageData{
			Intent: Intent{
				GrantType:      Command,
				Reserved:       0,
				TargetPort:     7777,
				StartTime:      time.Unix(startTime, 0),
				ExpTime:        time.Unix(expTime, 0),
				TargetSNI:      certs.RawStringName("target"),
				TargetUsername: "user",
				DelegateCert: certs.Certificate{
					Version:   1,
					Type:      certs.Leaf,
					IssuedAt:  time.Unix(int64(0x0102030405060708), 0),
					ExpiresAt: time.Unix(int64(0x0FEDCBA098765432), 0),
					IDChunk: certs.IDChunk{
						Blocks: []certs.Name{
							{
								Type:  certs.TypeDNSName,
								Label: []byte("example.domain"),
							},
						},
					},
					PublicKey: testKeyPair.public,
					Parent:    certs.SHA3Fingerprint{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
					Signature: fakeSignature(),
				},
				AssociatedData: GrantData{CommandGrantData: CommandGrantData{
					Cmd: cmd,
				}},
			},
		},
	}
	return msg
}

func fakeDelegate(t *testing.T, c net.Conn) {
	msg := getTestCmdIntentRequest(t, "echo hello world")
	_, err := msg.WriteTo(c)
	assert.NilError(t, err)
	resp, err := ReadConfOrDenial(c)
	assert.NilError(t, err)
	if resp.MsgType == IntentDenied {
		logrus.Infof("delegate: got intent denied: %s", resp.Data.Denial)
	} else {
		logrus.Info("delegate: got conf")
	}
	c.Close()
}

func fakeTarget(t *testing.T, c net.Conn) {
	_, err := ReadIntentCommunication(c)
	assert.NilError(t, err)
	logrus.Info("target: got intent comm")
	err = SendIntentConfirmation(c)
	assert.NilError(t, err)
}

func fakeTargetLoop(t *testing.T, c net.Conn) {
	for {
		_, err := ReadIntentCommunication(c)
		if err != nil {
			break
		}
		logrus.Info("target: got intent comm")
		err = SendIntentConfirmation(c)
		assert.NilError(t, err)
	}
	logrus.Info("fake target: stopped looping")
}

func fakeTargetDenial(t *testing.T, c net.Conn) {
	_, err := ReadIntentCommunication(c)
	assert.NilError(t, err)
	logrus.Info("target: got intent comm")
	err = SendIntentDenied(c, "target says so")
	assert.NilError(t, err)
}

func TestPrincipal(t *testing.T) {
	dc, dcD := net.Pipe() // delegate conn
	tc, tcT := net.Pipe() // target conn

	ciFunc := func(Intent) error {
		logrus.Info("principal: checking intent")
		return nil
	}

	setupTarg := func(u core.URL) (net.Conn, error) {
		logrus.Infof("target setup: simulating connection to %s", u.String())
		return tc, nil
	}

	// Start "Delegate"
	go fakeDelegate(t, dcD)

	// Start "Target"
	go fakeTarget(t, tcT)

	StartPrincipalInstance(dc, ciFunc, setupTarg)
}

func TestPrincipalNilCallback(t *testing.T) {
	dc, dcD := net.Pipe() // delegate conn
	tc, tcT := net.Pipe() // target conn

	setupTarg := func(u core.URL) (net.Conn, error) {
		logrus.Infof("target setup: simulating connection to %s", u.String())
		return tc, nil
	}

	// Start "Delegate"
	go fakeDelegate(t, dcD)

	// Start "Target"
	go fakeTarget(t, tcT)

	StartPrincipalInstance(dc, nil, setupTarg)
}

func TestPrincipalCheckIntentFail(t *testing.T) {
	dc, dcD := net.Pipe() // delegate conn
	tc, tcT := net.Pipe() // target conn

	ciFunc := func(Intent) error {
		logrus.Info("principal: checking intent")
		return fmt.Errorf("not going to approve that")
	}

	setupTarg := func(u core.URL) (net.Conn, error) {
		logrus.Infof("target setup: simulating connection to %s", u.String())
		return tc, nil
	}

	// Start "Delegate"
	go fakeDelegate(t, dcD)

	// Start "Target"
	go fakeTarget(t, tcT)

	StartPrincipalInstance(dc, ciFunc, setupTarg)
}

func TestPrincipalCheckTargetFail(t *testing.T) {
	dc, dcD := net.Pipe() // delegate conn
	tc, tcT := net.Pipe() // target conn

	ciFunc := func(Intent) error {
		logrus.Info("principal: checking intent")
		return nil
	}

	setupTarg := func(u core.URL) (net.Conn, error) {
		logrus.Infof("target setup: simulating connection to %s", u.String())
		return tc, nil
	}

	// Start "Delegate"
	go fakeDelegate(t, dcD)

	// Start "Target"
	go fakeTargetDenial(t, tcT)

	StartPrincipalInstance(dc, ciFunc, setupTarg)
}
