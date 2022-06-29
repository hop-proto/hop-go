package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"hop.computer/hop/core"
	"hop.computer/hop/flags"
	"hop.computer/hop/hopclient"
)

func main() {
	f := new(flags.ClientFlags)
	fs := new(flag.FlagSet)

	var isRemote bool
	fs.BoolVar(&isRemote, "t", false, "run hcp in remote mode. Read from stdin and write to a file")
	flags.DefineClientFlags(fs, f)

	err := fs.Parse(os.Args[1:])
	if err != nil {
		logrus.Error(err)
		return
	}

	if !isRemote && fs.NArg() < 2 {
		logrus.Error("Usage: hcp source target")
		return
	}

	if isRemote {
		logrus.Info("Running as server")
		server(fs.Arg(0))
	} else {
		logrus.Info("Running as client")
		srcURL, srcFile := parsePath(fs.Arg(0))
		dstURL, dstFile := parsePath(fs.Arg(1))
		client(srcURL, srcFile, dstURL, dstFile, f)
	}
}

func parsePath(path string) (string, string) {
	arr := strings.Split(path, ":")

	url := ""
	file := arr[len(arr)-1]

	if len(arr) > 1 {
		url = strings.Join(arr[:len(arr)-1], ":")
	}
	return url, file
}

func server(dstFile string) {
	logrus.Info("Do we have echo???")
	remoteFile, err := os.Create(dstFile)
	if err != nil {
		logrus.Error(err)
		return
	}

	_, err = io.Copy(remoteFile, os.Stdin)
	if err != nil {
		logrus.Error(err)
		return
	}
}

func client(srcURL string, srcFile string, dstURL string, dstFile string, f *flags.ClientFlags) {
	if !(srcURL == "" && dstURL != "") {
		logrus.Error("TODO: Currently only supports local to remote copying")
		return
	}

	addr, err := core.ParseURL(dstURL)
	if err != nil {
		logrus.Error(err)
		return
	}
	f.Address = addr

	// cc will be result of merging config file settings and flags
	cc, err := flags.LoadClientConfigFromFlags(f)
	if err != nil {
		logrus.Error(err)
		return
	}

	cc.Shell = false
	cc.Cmd = fmt.Sprintf("/go/bin/hcp -t %s", dstFile)

	localFile, err := os.Open(srcFile)
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
	client.Start()
	defer client.Wait()
	defer func() {
		err = client.ExecTube.Close()
		if err != nil {
			logrus.Error(err)
		}
	}()

	_, err = io.Copy(client.ExecTube.Tube, localFile)
	if err != nil {
		logrus.Error(err)
		return
	}
	logrus.Info("Done copying")
}
