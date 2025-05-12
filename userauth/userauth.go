// Package userauth allows servers/clients to determine user authorization
package userauth

import (
	"encoding/binary"
	"io"

	"hop.computer/hop/tubes"
)

const (
	headerLen = 2
)

type userAuthInitMsg struct {
	username string
}

// Server tells client whether user authorization confirmed or denied
const (
	UserAuthConf = byte(1)
	UserAuthDen  = byte(2)
)

func newUserAuthInitMsg(user string) *userAuthInitMsg {
	return &userAuthInitMsg{
		username: user,
	}
}

func (msg *userAuthInitMsg) toBytes() []byte {
	length := headerLen + len(msg.username)
	s := make([]byte, length)
	binary.BigEndian.PutUint16(s[0:headerLen], uint16(len(msg.username)))
	copy(s[headerLen:], []byte(msg.username))
	return s
}

// RequestAuthorization used by client to send username and get server confirmation or denial
func RequestAuthorization(ch *tubes.Reliable, username string) bool {
	ch.Write(newUserAuthInitMsg(username).toBytes())
	//add timeout
	b := make([]byte, 1)
	io.ReadFull(ch, b)
	return b[0] == UserAuthConf
}

// GetInitMsg lets the hop server read a user auth request
func GetInitMsg(ch *tubes.Reliable) string {
	lbuf := make([]byte, headerLen)
	io.ReadFull(ch, lbuf)
	length := binary.BigEndian.Uint16(lbuf[:])
	buf := make([]byte, length)
	io.ReadFull(ch, buf)
	return string(buf)
}
