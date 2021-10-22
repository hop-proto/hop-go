package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/app"
)

// must run with privileged user or with sudo at the moment
// ./hopd 			--> starts server on <hostname>:7777
// ./hopd <port> 	--> starts server on <hostname>:<port>

// ./hopd local 		--> starts server on <localhost>:7777
// ./hopd local <port> 	--> starts server on <localhost>:<port>

func main() {
	logrus.Infof("Hosting hop server daemon")
	app.Serve(os.Args) //start "hop server daemon process"
}
