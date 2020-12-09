package main

import (
	"flag"

	"zmap.io/portal"
)

var server bool

func main() {
	flag.BoolVar(&server, "server", false, "specifies client/server")
	flag.Parse()
	if server {
		serverApp()
	} else {
		clientApp()
	}
}

func clientApp() {
	// TODO
}

func serverApp() {
	config := portal.Config{}
	listener, err := portal.Listen("udp", "127.0.0.1:0", &config)
	if err != nil {
		panic(err)
	}
	listener.Accept()
	// TODO
}
