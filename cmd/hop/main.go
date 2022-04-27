package main

import (
	"os"

	"github.com/sirupsen/logrus"

	"zmap.io/portal/flags"
	"zmap.io/portal/hopclient"
)

func main() {
	f, err := flags.ParseArgs(os.Args)
	if err != nil {
		logrus.Error(err)
		return
	}
	cc, err := flags.LoadConfigFromFlags(f)
	if err != nil {
		logrus.Error(err)
		return
	}
	// Combine the CLI Flags and the ClientConfig with appropriate override
	config, address := flags.ClientSetup(f)
	client, err := hopclient.NewHopClient(config)
	if err != nil {
		logrus.Error(err)
		return
	}

	// Make authenticator using info in config
	authenticator, err := flags.AuthenticatorSetup(cc, f)
	if err != nil {
		logrus.Error(err)
		return
	}

	err = client.Dial(address, authenticator)
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
