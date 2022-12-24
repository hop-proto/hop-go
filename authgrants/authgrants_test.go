package authgrants

import (
	"bytes"
	"crypto/rand"
	"testing"

	"gotest.tools/assert"

	"hop.computer/hop/certs"
)

func TestAgMessageDenialEncodeDecode(t *testing.T) {
	b := &bytes.Buffer{}
	msg := AgMessage{
		MsgType: IntentDenied,
		Data:    MessageData{Denial: "I say so"},
	}

	recMsg := new(AgMessage)
	n, err := msg.WriteTo(b)
	assert.NilError(t, err)
	m, err := recMsg.ReadFrom(b)
	assert.NilError(t, err)
	assert.Equal(t, n, m)

}

// copied cert stuff from certificate_test.go
type keypair struct {
	public, private [certs.KeyLen]byte
}

func fakeSignature() [certs.SignatureLen]byte {
	var out [certs.SignatureLen]byte
	rand.Read(out[:])
	return out
}

func TestAgMessageIntentEncodeDecode(t *testing.T) {
	b := &bytes.Buffer{}
	var testKeyPair keypair
	rand.Read(testKeyPair.public[:])
	rand.Read(testKeyPair.private[:])
	msg := getTestIntentRequest(t)

	recMsg := new(AgMessage)
	n, err := msg.WriteTo(b)
	assert.NilError(t, err)
	m, err := recMsg.ReadFrom(b)
	assert.NilError(t, err)
	assert.Equal(t, n, m)
	assert.Equal(t, msg.MsgType, recMsg.MsgType)
	assert.Equal(t, msg.Data.Denial, recMsg.Data.Denial)
	assert.Equal(t, msg.Data.Intent.GrantType, recMsg.Data.Intent.GrantType)
	assert.Equal(t, msg.Data.Intent.Reserved, recMsg.Data.Intent.Reserved)
	assert.Equal(t, msg.Data.Intent.TargetPort, recMsg.Data.Intent.TargetPort)
	assert.DeepEqual(t, msg.Data.Intent.StartTime, recMsg.Data.Intent.StartTime)
	assert.DeepEqual(t, msg.Data.Intent.ExpTime, recMsg.Data.Intent.ExpTime)
	assert.DeepEqual(t, msg.Data.Intent.TargetSNI, recMsg.Data.Intent.TargetSNI)
	assert.Equal(t, msg.Data.Intent.TargetUsername, recMsg.Data.Intent.TargetUsername)
	buf, err := msg.Data.Intent.DelegateCert.Marshal()
	assert.NilError(t, err)
	recBuf, err := recMsg.Data.Intent.DelegateCert.Marshal()
	assert.NilError(t, err)
	assert.DeepEqual(t, buf, recBuf)
}
