package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/app"
)

//Usage: hop [user@]host[:port] [-K or -k path] [-c cmd]

func main() {
	logrus.Infof("Starting hop client")
	err := app.Client(os.Args)
	if err != nil {
		logrus.Error(err)
	}
}
