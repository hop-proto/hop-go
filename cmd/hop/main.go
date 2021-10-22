package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/app"
)

func main() {
	err := app.Client(os.Args)
	if err != nil {
		logrus.Error("Main: ", err)
	}
}
