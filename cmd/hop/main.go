package main

import (
	"net/http"
	_ "net/http/pprof"

	"os"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"

	"hop.computer/hop/flags"
	"hop.computer/hop/hopclient"
)

func main() {
	go func() {
		logrus.Info(http.ListenAndServe("localhost:8080", nil))
	}()
	f, err := flags.ParseClientArgs(os.Args)
	if err != nil {
		logrus.Error(err)
		return
	}

	// TODO(baumanl): better options for enabling logging to file/level
	if f.Verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
	logrus.SetLevel(logrus.DebugLevel)
	// default log at info level to file --> otherwise things get really
	// confusing when running authgrant protocol and all processes are trying
	// to log to std err.
	file, err := os.CreateTemp("/tmp", "hop*.log")
	if err != nil {
		logrus.Error("unable to create log file")
	} else {
		logrus.SetOutput(file)
	}

	// hc will be result of merging config file settings and flags
	hc, err := flags.LoadClientConfigFromFlags(f)
	if err != nil {
		if perr, ok := err.(toml.ParseError); ok {
			logrus.Error(perr.ErrorWithUsage())
		} else {
			logrus.Error(err)
		}
		return
	}

	client, err := hopclient.NewHopClient(hc)
	if err != nil {
		logrus.Error(err)
		return
	}

	client.RawConfigFilePath = f.ConfigPath

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

	err = client.Close()
	if err != nil {
		logrus.Errorf("Error closing client: %s", err)
	}
}
