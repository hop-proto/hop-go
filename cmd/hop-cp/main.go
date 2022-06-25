package main

import (
	"flag"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/flags"
	"hop.computer/hop/hopclient"
)

func main() {

	f := new(flags.ClientFlags)
	fs := new(flag.FlagSet)
	fs.StringVar(&f.ConfigPath, "C", "", "path to client config (uses ~/.hop/config when unspecified)")
	err := fs.Parse(os.Args[1:])
	if err != nil {
		logrus.Error(err)
		return
	}
	
	if fs.NArg() < 2 {
		logrus.Error("Usage: hop-cp source target")
		return
	}

	src_arr := strings.Split(fs.Arg(0), ":")
	if len(src_arr) == 1 {
		src_url = nil
		src_file := src_arr[0]
	} else {
		src_url := src_arr[0]
		src_file := src_arr[1]
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
