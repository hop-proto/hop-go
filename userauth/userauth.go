package userauth

import (
	"encoding/binary"

	"zmap.io/portal/keys"
	"zmap.io/portal/tubes"
)

const (
	headerLen         = 36
	keyOffset         = 0
	usernameLenOffset = 32
	usernameOffset    = 36
)

type userAuthInitMsg struct {
	key      keys.PublicKey
	username string
}

const (
	UserAuthConf = byte(1)
	UserAuthDen  = byte(2)
)

func newUserAuthInitMsg(key keys.PublicKey, user string) *userAuthInitMsg {
	return &userAuthInitMsg{
		key:      key,
		username: user,
	}
}

func (msg *userAuthInitMsg) toBytes() []byte {
	length := headerLen + len(msg.username)
	s := make([]byte, length)
	copy(s[keyOffset:usernameLenOffset], msg.key[:])
	binary.BigEndian.PutUint16(s[usernameLenOffset:usernameOffset], uint16(len(msg.username)))
	copy(s[usernameOffset:], []byte(msg.username))
	return s
}

//RequestAuthorization used by client to send username and key and get server confirmation or denial
func RequestAuthorization(ch *tubes.Reliable, key keys.PublicKey, username string) bool {
	ch.Write(newUserAuthInitMsg(key, username).toBytes())
	//add timeout
	b := make([]byte, 1)
	ch.Read(b)
	return b[0] == UserAuthConf
}

func GetInitMsg(ch *tubes.Reliable) (keys.PublicKey, string) {
	key := [32]byte{}
	ch.Read(key[:])
	lbuf := make([]byte, 4)
	ch.Read(lbuf)
	length := binary.BigEndian.Uint16(lbuf[:])
	buf := make([]byte, length)
	ch.Read(buf)
	return key, string(buf)
}
