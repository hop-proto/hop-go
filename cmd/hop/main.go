package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/app"
)

// ./hop <username>@<host>:<port> -k path (for principal)
// ./hop <username>@<host>:<port> -a action (for auth grant)

func main() {
	logrus.Infof("Starting hop client")
	app.Client(os.Args)
}
