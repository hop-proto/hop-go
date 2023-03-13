package main

import (
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
	logrus.SetLevel(logrus.DebugLevel)
	f, err := flags.ParseHcpArgs(os.Args)
	if err != nil {
		logrus.Error(err)
		return
	}
 
	if f.IsRemote {
		logrus.Info("Running as server")
		server(f)
	} else {
		logrus.Info("Running as client")
		client(f)
	}
}

func parsePath(path string) (*core.URL, string, error) {
	arr := strings.Split(path, ":")

	urlStr := ""
	file := arr[len(arr)-1]

	var url *core.URL = nil
	var err error
	if len(arr) > 1 {
		urlStr = strings.Join(arr[:len(arr)-1], ":")
		url, err = core.ParseURL(urlStr)
		if err != nil {
			return nil, "", err
		}
	}
	return url, file, nil
}

func server(f *flags.HcpFlags) {
	if f.IsSource {
		logrus.Info("source for copy")
		remoteFd, err := os.Open(f.SrcFile)
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
		logrus.Info("destination for copy")
		remoteFd, err := os.Create(f.DstFile)
		logrus.Info("created destination file")
		if err != nil {
			logrus.Error(err)
			return
		}

		logrus.Info("copying from stdin")
		_, err = io.Copy(remoteFd, os.Stdin)
		logrus.Info("copying done")
		if err != nil {
			logrus.Error(err)
			return
		}
	}
}

func client(f *flags.HcpFlags) {
	srcURL, srcFile, err := parsePath(f.SrcFile)
	if err != nil {
		logrus.Error(err)
		return
	}
	dstURL, dstFile, err := parsePath(f.DstFile)
	if err != nil {
		logrus.Error(err)
		return
	}

	var addr *core.URL
	if srcURL == nil && dstURL != nil { // local to remote case
		addr = dstURL
	} else if srcURL != nil && dstURL == nil { // remote to local case
		addr = srcURL
	} else if srcURL == nil && dstURL == nil { // local to local case
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
	f.Flags.Address = addr


	srcFlag := ""
	if srcURL != nil {
		srcFlag = "-s"
	}
	f.Flags.Cmd = fmt.Sprintf("/go/bin/hcp -t %s %s %s", srcFlag, srcFile, dstFile)

	var localFd *os.File
	if srcURL == nil { // local to remote, read from local filesystem
		localFd, err = os.Open(srcFile)
	} else { // remote to local, write to local filesystem
		localFd, err = os.Create(dstFile)
	}
	if err != nil {
		logrus.Error(err)
		return
	}

	hc, err := flags.LoadClientConfigFromFlags(f.Flags)
	if err != nil {
		logrus.Error(err)
		return
	}

	client, err := hopclient.NewHopClient(hc)
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
	}

	if srcURL == nil { // local to remote, read from local filesystem
		_, err = io.Copy(client.ExecTube.Tube, localFd)
	} else { // remote to local, write to local file system
		_, err = io.Copy(localFd, client.ExecTube.Tube)
	}
	if err != nil {
		logrus.Errorf("error copying: %v", err)
		return
	}

	logrus.Info("Done copying")
	err = client.ExecTube.Tube.Close()
	if err != nil {
		logrus.Errorf("error closing tube: %v", err)
	}

	client.Wait()

	err = client.Close()
	if err != nil {
		logrus.Errorf("Error closing connection: %v", err)
	}
	return

}
