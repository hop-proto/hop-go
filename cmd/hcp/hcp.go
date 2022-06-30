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
	var isSource bool
	fs.BoolVar(&isRemote, "t", false, "run hcp in remote mode")
	fs.BoolVar(&isSource, "s", false, "if running in remote mode read from file and write to stdout")
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
		server(fs.Arg(0), isSource)
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

func server(remoteFile string, isSource bool) {
	if isSource {
		remoteFd, err := os.Open(remoteFile)
		if err != nil {
			logrus.Error(err)
			return
		}

		_, err = io.Copy(os.Stdout, remoteFd)
		if err != nil {
			logrus.Error(err)
			return
		}
	} else {
		remoteFd, err := os.Create(remoteFile)
		if err != nil {
			logrus.Error(err)
			return
		}

		n, err := io.Copy(remoteFd, os.Stdin)
		if err != nil {
			logrus.Error(err)
			return
		} else {
			logrus.Errorf("Wrote %d bytes", n)
		}
	}
}

func client(srcURL string, srcFile string, dstURL string, dstFile string, f *flags.ClientFlags) {

	var addr *core.URL
	var err error
	if srcURL == "" && dstURL != "" { // local to remote case
		addr, err = core.ParseURL(dstURL)
		if err != nil {
			logrus.Error(err)
			return
		}
	} else if srcURL != "" && dstURL == "" { // remote to local case
		addr, err = core.ParseURL(srcURL)
		if err != nil {
			logrus.Error(err)
			return
		}
	} else if srcURL == "" && dstURL == "" { // local to local case
		dstFd, err := os.Create(dstFile)
		if err != nil {
			logrus.Error(err)
			return
		}
		srcFd, err := os.Open(srcFile)
		if err != nil {
			logrus.Error(err)
			return
		}
		io.Copy(dstFd, srcFd)
		return
	} else { // TODO(hosono) remote to remote case
		logrus.Error("TODO: remote to remote case")
	}
	f.Address = addr

	// cc will be result of merging config file settings and flags
	cc, err := flags.LoadClientConfigFromFlags(f)
	if err != nil {
		logrus.Error(err)
		return
	}

	cc.Shell = false

	if srcURL == "" {
		cc.Cmd = fmt.Sprintf("/go/bin/hcp -t %s", dstFile)
	} else {
		// read from remote server
		cc.Cmd = fmt.Sprintf("/go/bin/hcp -t -s %s", srcFile)
	}

	var localFd *os.File
	if srcURL == "" { // local to remote, read from local filesystem
		localFd, err = os.Open(srcFile)
	} else { // remote to local, write to local filesystem
		localFd, err = os.Create(dstFile)
	}
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

	if srcURL == "" { // local to remote, read from local filesystem
		_, err = io.Copy(client.ExecTube.Tube, localFd)
	} else { // remote to local, write to local file system
		_, err = io.Copy(localFd, client.ExecTube.Tube)
	}
	if err != nil {
		logrus.Error(err)
		return
	}
	logrus.Info("Done copying")
}
