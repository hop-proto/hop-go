package main

import (
	"os"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/flags"
	"hop.computer/hop/hopclient"
)

func main() {
	f, err := flags.ParseClientArgs(os.Args)
	if err != nil {
		logrus.Error(err)
		return
	}
	// cc will be result of merging config file settings and flags
	cc, err := flags.LoadClientConfigFromFlags(f)
	if err != nil {
		logrus.Error(err)
		return
	}

	client, err := hopclient.NewHopClient(cc, f.Address.Host)
	if err != nil {
		logrus.Error(err)
		return
	}

	err = client.Dial()
	if err != nil {
		logrus.Error(err)
		return
	}
	err = client.Start()
	if err != nil {
		logrus.Error(err)
		return
	}
}
