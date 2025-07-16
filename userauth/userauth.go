// Package userauth allows servers/clients to determine user authorization
package userauth

import (
	"encoding/binary"
	"github.com/sirupsen/logrus"
	"io"

	"hop.computer/hop/tubes"
)

const (
	headerLen         = 4
	usernameLenOffset = 0
	usernameOffset    = 2
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
	binary.BigEndian.PutUint16(s[usernameLenOffset:usernameOffset], uint16(len(msg.username)))
	copy(s[usernameOffset:], []byte(msg.username))
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
	lbuf := make([]byte, 2)
	io.ReadFull(ch, lbuf)
	length := binary.BigEndian.Uint16(lbuf[:])
	if length == 0 {
		logrus.Debugf("S: get init message user auth has a lenght of 0")
	}
	buf := make([]byte, length)
	io.ReadFull(ch, buf)
	if string(buf) == "" {
		logrus.Debugf("S: get init message user auth has a empty string username")
	}
	return string(buf)
}
