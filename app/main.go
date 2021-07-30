package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/keys"
)

//If on principal: hop user@host:port -k <pathtokey>
//If on intermediate: hop user@host:port -a <action>

//Demo:
//principal: go run *.go hop user@127.0.0.1:8888 -k path
//server1: go run *.go hopd 1
//server2: go run *.go hopd 2

func main() {
	if os.Args[1] == "hop" {
		logrus.Infof("Starting hop client")
		client(os.Args)
	} else if os.Args[1] == "hopd" {
		logrus.Infof("Hosting hop server daemon")
		serve(os.Args) //start "hop server daemon process"
	} else if os.Args[1] == "add" {
		//add a key
		pair := new(keys.X25519KeyPair)
		pair.Generate()
		f, e := os.OpenFile("keys/default", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
		if e != nil {
			logrus.Fatalf("error opening default key file: ", e)
		}
		defer f.Close()
		logrus.Infof("adding private to keys/default", pair.Private.String())
		f.WriteString(pair.Private.String())

		auth, e := os.OpenFile("authorized_keys", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
		if e != nil {
			logrus.Fatalf("error opening auth key file: ", e)
		}
		defer auth.Close()
		logrus.Infof("adding public to auth keys: %v", pair.Public.String())
		auth.WriteString(pair.Public.String())
		auth.WriteString("\n")
	} else {
		logrus.Fatal("Unrecognized command")
	}
}
