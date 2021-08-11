package main

import (
	"errors"
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/keys"
)

func main() { //add a key
	pair := new(keys.X25519KeyPair)
	pair.Generate()
	path, _ := os.UserHomeDir()
	path += "/.hop/key"
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		logrus.Info("file does not exist, creating...")
		f, e := os.Create(path)
		if e != nil {
			logrus.Error(e)
		}
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
		if e != nil {
			logrus.Error(e)
		}
		f.Close()
	}
	f, e = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if e != nil {
		logrus.Fatalf("error opening default key file: %v", e)
	}
	logrus.Infof("adding public to ~/.hop/key.pub: %v", pair.Public.String())
	f.WriteString(pair.Public.String())
	f.Close()

	path, _ = os.UserHomeDir()
	path += "/.hop/authorized_keys" //adds the key to its own authorized key file so that localhost operations will work
	_, err = os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		logrus.Info("file does not exist, creating...")
		f, e := os.Create(path)
		if e != nil {
			logrus.Error(e)
		}
		f.Close()
	}
	auth, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if e != nil {
		logrus.Fatalf("error opening auth key file: %v", e)
	}
	defer auth.Close()
	logrus.Infof("adding public to auth keys: %v", pair.Public.String())
	auth.WriteString(pair.Public.String())
	auth.WriteString("\n")
}
