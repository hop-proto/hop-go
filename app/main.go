package main

import (
	"errors"
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/keys"
)

//If on principal: hop <user>@<host>:<port> -k <pathtokey>
//If on intermediate: hop <user>@<host>:<port> -a <action>

//Demo:
//server1: 			go run *.go hopd 1 							(will run on localhost port 7777)
//server2: 			go run *.go hopd 2 							(will run on localhost port 8888)
//server3: 			go run *.go hopd 3 							(will run on localhost port 9999)
//principal: 		go run *.go hop user@127.0.0.1:7777 -k path ("path" will use default keys I set up in app folder or you can put in an actual filename)
//p -> s1: 			go run *.go hop user@127.0.0.1:8888 -a bash
//p -> s1 -> s2: 	go run *.go hop user@127.0.0.1:9999 -a bash

//Actions besides bash work, but closing/ending behavior is still rough,
//so issues might come up after a oneshot command is finished running.

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
		path, _ := os.UserHomeDir()
		path += "/.hop/key"
		_, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			logrus.Info("file does not exist, creating...")
			f, e := os.Create(path)
			logrus.Error(e)
			f.Close()
		}
		f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
		if e != nil {
			logrus.Fatalf("error opening default key file: %v", e)
		}
		logrus.Infof("adding private to ~/.hop/key: %v", pair.Private.String())
		f.WriteString(pair.Private.String())
		f.Close()

		path, _ = os.UserHomeDir()
		path += "/.hop/key.pub"
		_, err = os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			logrus.Info("file does not exist, creating...")
			f, e := os.Create(path)
			logrus.Error(e)
			f.Close()
		}
		_, err = os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			f, _ := os.Create(path)
			f.Close()
		}
		f, e = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
		if e != nil {
			logrus.Fatalf("error opening default key file: %v", e)
		}
		logrus.Infof("adding public to ~/.hop/key.pub: %v", pair.Public.String())
		f.WriteString(pair.Public.String())
		f.Close()

		auth, e := os.OpenFile("~/.hop/authorized_keys", os.O_APPEND|os.O_WRONLY, os.ModeAppend)
		if e != nil {
			logrus.Fatalf("error opening auth key file: %v", e)
		}
		defer auth.Close()
		logrus.Infof("adding public to auth keys: %v", pair.Public.String())
		auth.WriteString(pair.Public.String())
		auth.WriteString("\n")
	} else {
		logrus.Fatal("Unrecognized command")
	}
}
