package authgrants

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

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
	startTime := time.Now().Unix()
	expTime := time.Now().Add(time.Hour).Unix()
	b := &bytes.Buffer{}
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
					Cmd: "echo hello world",
				}},
			},
		},
	}

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
