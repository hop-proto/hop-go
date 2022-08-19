package main

import (
	"os"
	"time"

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

	// TODO (hosono) verbose logging seems to prevent hop from working. Concurrency bug?
	if f.Verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// cc will be result of merging config file settings and flags
	cc, err := flags.LoadClientConfigFromFlags(f)
	if err != nil {
		logrus.Error(err)
		return
	}
	cc.Global.HandshakeTimeout = 15 * time.Second
	cc.Global.DataTimeout = 15 * time.Second

	client, err := hopclient.NewHopClientWithURL(cc, f.Address)
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
