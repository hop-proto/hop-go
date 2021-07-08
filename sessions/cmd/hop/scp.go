package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"strings"
)

// The SCP copy mode, from the perspective of the remote.
const (
	SOURCE uint = iota
	SINK   uint = iota
)

func parseRemotePath(remotePath string) (string, string, error) {
	if !strings.Contains(remotePath, ":") {
		return "", "", errors.New("Invalid remote path - must be of form user@host:path")
	}
	split := strings.Split(remotePath, ":")
	return split[0], split[1], nil
}

func parsePaths(sourcePath string, destPath string) (uint, string, string, string, error) {

	if strings.Contains(sourcePath, ":") == strings.Contains(destPath, ":") {
		return 0, "", "", "", errors.New("Only one of src, dest should fetch a remote host.")
	}
	var mode uint
	var userHost string
	var err error
	if strings.Contains(sourcePath, ":") {
		mode = SINK
		userHost, sourcePath, err = parseRemotePath(sourcePath)
		if err != nil {
			return 0, "", "", "", err
		}
	} else if strings.Contains(destPath, ":") {
		mode = SOURCE
		userHost, destPath, err = parseRemotePath(destPath)
		if err != nil {
			return 0, "", "", "", err
		}
	}
	return mode, userHost, sourcePath, destPath, nil
}

func scp(sourcePath string, destPath string) error {

	mode, _, sourcePath, destPath, err := parsePaths(sourcePath, destPath)
	if err != nil || (mode != SOURCE && mode != SINK) {
		return err
	}
	// TODO(drew): support both copy modes.

	client, err := getClient()
	if err != nil {
		return err
	}
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	writer, err := session.StdinPipe()
	if err != nil {
		return err
	}
	reader, err := session.StdoutPipe()
	if err != nil {
		return err
	}

	path := sourcePath
	if mode == SOURCE {
		path = destPath
	}
	payload, err := serializePayload(mode, path)
	if err != nil {
		return err
	}
	session.SendRequest("scp", false, payload)
	if mode == SOURCE {
		err := sendFile(writer, sourcePath)
		if err != nil {
			return err
		}
	} else if mode == SINK {
		err := receiveFile(reader, destPath)
		if err != nil {
			return err
		}
	}

	return nil
}

func receiveFile(r io.Reader, destPath string) error {
	file, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer file.Close()
	buf := make([]byte, 1024)
	for {

		chunk, err := r.Read(buf)
		if err != nil {
			return err
		}
		if chunk == 0 {
			break
		}
		_, err = file.Write(buf[:chunk])
		if err != nil {
			return err
		}
	}
	return nil
}

func sendFile(w io.Writer, srcPath string) error {
	file, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer file.Close()

	buf := make([]byte, 1024)
	for {
		chunk, err := file.Read(buf)
		log.Printf("Sending %d bytes\n", chunk)
		if err != nil {
			return err
		}
		if chunk == 0 {
			break
		}
		_, err = w.Write(buf[:chunk])
		if err != nil {
			return err
		}
	}
	return nil
}

type SCPRequestPayload struct {
	Mode uint   `json:"mode"`
	Path string `json:"path"`
}

func serializePayload(mode uint, path string) ([]byte, error) {
	return json.Marshal(SCPRequestPayload{mode, path})
}
